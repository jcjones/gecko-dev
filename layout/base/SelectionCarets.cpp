/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 sw=2 et tw=78: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "prlog.h"
#include "SelectionCarets.h"

#include "gfxPrefs.h"
#include "nsBidiPresUtils.h"
#include "nsCanvasFrame.h"
#include "nsCaret.h"
#include "nsContentUtils.h"
#include "nsDebug.h"
#include "nsDocShell.h"
#include "nsDOMTokenList.h"
#include "nsFocusManager.h"
#include "nsFrame.h"
#include "nsIDocument.h"
#include "nsIDocShell.h"
#include "nsIDOMDocument.h"
#include "nsIDOMNodeFilter.h"
#include "nsIPresShell.h"
#include "nsPresContext.h"
#include "nsRect.h"
#include "nsView.h"
#include "mozilla/dom/DOMRect.h"
#include "mozilla/dom/Element.h"
#include "mozilla/dom/ScrollViewChangeEvent.h"
#include "mozilla/dom/Selection.h"
#include "mozilla/dom/TreeWalker.h"
#include "mozilla/Preferences.h"
#include "mozilla/TouchEvents.h"
#include "TouchCaret.h"
#include "nsFrameSelection.h"

using namespace mozilla;
using namespace mozilla::dom;

#ifdef PR_LOGGING
static PRLogModuleInfo* gSelectionCaretsLog;
static const char* kSelectionCaretsLogModuleName = "SelectionCarets";

// To enable all the SELECTIONCARETS_LOG print statements, set the environment
// variable NSPR_LOG_MODULES=SelectionCarets:5
#define SELECTIONCARETS_LOG(message, ...)                                      \
  PR_LOG(gSelectionCaretsLog, PR_LOG_DEBUG,                                    \
         ("SelectionCarets (%p): %s:%d : " message "\n", this, __FUNCTION__,   \
          __LINE__, ##__VA_ARGS__));

#define SELECTIONCARETS_LOG_STATIC(message, ...)                               \
  PR_LOG(gSelectionCaretsLog, PR_LOG_DEBUG,                                    \
         ("SelectionCarets: %s:%d : " message "\n", __FUNCTION__, __LINE__,    \
          ##__VA_ARGS__));
#else
#define SELECTIONCARETS_LOG(message, ...)
#define SELECTIONCARETS_LOG_STATIC(message, ...)
#endif // #ifdef PR_LOGGING

// We treat mouse/touch move as "REAL" move event once its move distance
// exceed this value, in CSS pixel.
static const int32_t kMoveStartTolerancePx = 5;
// Time for trigger scroll end event, in miliseconds.
static const int32_t kScrollEndTimerDelay = 300;
// Read from preference "selectioncaret.noneditable". Indicate whether support
// non-editable fields selection or not. We have stable state for editable
// fields selection now. And we don't want to break this stable state when
// enabling non-editable support. So I add a pref to control to support or
// not. Once non-editable fields support is stable. We should remove this
// pref.
static bool kSupportNonEditableFields = false;

NS_IMPL_ISUPPORTS(SelectionCarets,
                  nsIReflowObserver,
                  nsISelectionListener,
                  nsIScrollObserver,
                  nsISupportsWeakReference)

/*static*/ int32_t SelectionCarets::sSelectionCaretsInflateSize = 0;

SelectionCarets::SelectionCarets(nsIPresShell* aPresShell)
  : mPresShell(aPresShell)
  , mActiveTouchId(-1)
  , mCaretCenterToDownPointOffsetY(0)
  , mDragMode(NONE)
  , mAsyncPanZoomEnabled(false)
  , mEndCaretVisible(false)
  , mStartCaretVisible(false)
  , mSelectionVisibleInScrollFrames(true)
  , mVisible(false)
{
  MOZ_ASSERT(NS_IsMainThread());

#ifdef PR_LOGGING
  if (!gSelectionCaretsLog) {
    gSelectionCaretsLog = PR_NewLogModule(kSelectionCaretsLogModuleName);
  }
#endif

  SELECTIONCARETS_LOG("Constructor, PresShell=%p", mPresShell);

  static bool addedPref = false;
  if (!addedPref) {
    Preferences::AddIntVarCache(&sSelectionCaretsInflateSize,
                                "selectioncaret.inflatesize.threshold");
    Preferences::AddBoolVarCache(&kSupportNonEditableFields,
                                 "selectioncaret.noneditable");
    addedPref = true;
  }
}

void
SelectionCarets::Init()
{
  nsPresContext* presContext = mPresShell->GetPresContext();
  MOZ_ASSERT(presContext, "PresContext should be given in PresShell::Init()");

  nsIDocShell* docShell = presContext->GetDocShell();
  if (!docShell) {
    return;
  }

  docShell->GetAsyncPanZoomEnabled(&mAsyncPanZoomEnabled);
  mAsyncPanZoomEnabled = mAsyncPanZoomEnabled && gfxPrefs::AsyncPanZoomEnabled();

  docShell->AddWeakReflowObserver(this);
  docShell->AddWeakScrollObserver(this);

  mDocShell = static_cast<nsDocShell*>(docShell);
}

SelectionCarets::~SelectionCarets()
{
  SELECTIONCARETS_LOG("Destructor");
  MOZ_ASSERT(NS_IsMainThread());

  if (mLongTapDetectorTimer) {
    mLongTapDetectorTimer->Cancel();
    mLongTapDetectorTimer = nullptr;
  }

  if (mScrollEndDetectorTimer) {
    mScrollEndDetectorTimer->Cancel();
    mScrollEndDetectorTimer = nullptr;
  }

  mPresShell = nullptr;
}

void
SelectionCarets::Terminate()
{
  nsRefPtr<nsDocShell> docShell(mDocShell.get());
  if (docShell) {
    docShell->RemoveWeakReflowObserver(this);
    docShell->RemoveWeakScrollObserver(this);
  }

  mPresShell = nullptr;
}

nsEventStatus
SelectionCarets::HandleEvent(WidgetEvent* aEvent)
{
  WidgetMouseEvent *mouseEvent = aEvent->AsMouseEvent();
  if (mouseEvent && mouseEvent->reason == WidgetMouseEvent::eSynthesized) {
    return nsEventStatus_eIgnore;
  }

  WidgetTouchEvent *touchEvent = aEvent->AsTouchEvent();
  nsIntPoint movePoint;
  int32_t nowTouchId = -1;
  if (touchEvent && !touchEvent->touches.IsEmpty()) {
    // If touch happened, just grab event with same identifier
    if (mActiveTouchId >= 0) {
      for (uint32_t i = 0; i < touchEvent->touches.Length(); ++i) {
        if (touchEvent->touches[i]->Identifier() == mActiveTouchId) {
          movePoint = touchEvent->touches[i]->mRefPoint;
          nowTouchId = touchEvent->touches[i]->Identifier();
          break;
        }
      }

      // not found, consume it
      if (nowTouchId == -1) {
        return nsEventStatus_eConsumeNoDefault;
      }
    } else {
      movePoint = touchEvent->touches[0]->mRefPoint;
      nowTouchId = touchEvent->touches[0]->Identifier();
    }
  } else if (mouseEvent) {
    movePoint = LayoutDeviceIntPoint::ToUntyped(mouseEvent->AsGUIEvent()->refPoint);
  }

  // Get event coordinate relative to root frame
  nsIFrame* rootFrame = mPresShell->GetRootFrame();
  if (!rootFrame) {
    return nsEventStatus_eIgnore;
  }
  nsPoint ptInRoot =
    nsLayoutUtils::GetEventCoordinatesRelativeTo(aEvent, movePoint, rootFrame);

  if (aEvent->message == NS_TOUCH_START ||
      (aEvent->message == NS_MOUSE_BUTTON_DOWN &&
       mouseEvent->button == WidgetMouseEvent::eLeftButton)) {
    // If having a active touch, ignore other touch down event
    if (aEvent->message == NS_TOUCH_START && mActiveTouchId >= 0) {
      return nsEventStatus_eConsumeNoDefault;
    }

    mActiveTouchId = nowTouchId;
    mDownPoint = ptInRoot;
    if (IsOnStartFrameInner(ptInRoot)) {
      mDragMode = START_FRAME;
      mCaretCenterToDownPointOffsetY = GetCaretYCenterPosition() - ptInRoot.y;
      SetSelectionDirection(false);
      SetSelectionDragState(true);
      return nsEventStatus_eConsumeNoDefault;
    } else if (IsOnEndFrameInner(ptInRoot)) {
      mDragMode = END_FRAME;
      mCaretCenterToDownPointOffsetY = GetCaretYCenterPosition() - ptInRoot.y;
      SetSelectionDirection(true);
      SetSelectionDragState(true);
      return nsEventStatus_eConsumeNoDefault;
    } else {
      mDragMode = NONE;
      mActiveTouchId = -1;
      SetVisibility(false);
      LaunchLongTapDetector();
    }
  } else if (aEvent->message == NS_TOUCH_END ||
             aEvent->message == NS_TOUCH_CANCEL ||
             aEvent->message == NS_MOUSE_BUTTON_UP) {
    CancelLongTapDetector();
    if (mDragMode != NONE) {
      // Only care about same id
      if (mActiveTouchId == nowTouchId) {
        SetSelectionDragState(false);
        mDragMode = NONE;
        mActiveTouchId = -1;
      }
      return nsEventStatus_eConsumeNoDefault;
    }
  } else if (aEvent->message == NS_TOUCH_MOVE ||
             aEvent->message == NS_MOUSE_MOVE) {
    if (mDragMode == START_FRAME || mDragMode == END_FRAME) {
      if (mActiveTouchId == nowTouchId) {
        ptInRoot.y += mCaretCenterToDownPointOffsetY;
        return DragSelection(ptInRoot);
      }

      return nsEventStatus_eConsumeNoDefault;
    }

    nsPoint delta = mDownPoint - ptInRoot;
    if (NS_hypot(delta.x, delta.y) >
          nsPresContext::AppUnitsPerCSSPixel() * kMoveStartTolerancePx) {
      CancelLongTapDetector();
    }
  } else if (aEvent->message == NS_MOUSE_MOZLONGTAP) {
    if (!mVisible) {
      SELECTIONCARETS_LOG("SelectWord from APZ");
      SelectWord();
      return nsEventStatus_eConsumeNoDefault;
    }
  }
  return nsEventStatus_eIgnore;
}

static void
SetElementVisibility(dom::Element* aElement, bool aVisible)
{
  if (!aElement) {
    return;
  }

  ErrorResult err;
  aElement->ClassList()->Toggle(NS_LITERAL_STRING("hidden"),
                                   dom::Optional<bool>(!aVisible), err);
}

void
SelectionCarets::SetVisibility(bool aVisible)
{
  if (!mPresShell) {
    return;
  }

  if (mVisible == aVisible) {
    SELECTIONCARETS_LOG("Set visibility %s, same as the old one",
                        (aVisible ? "shown" : "hidden"));
    return;
  }

  mVisible = aVisible;
  SELECTIONCARETS_LOG("Set visibility %s", (mVisible ? "shown" : "hidden"));

  dom::Element* startElement = mPresShell->GetSelectionCaretsStartElement();
  SetElementVisibility(startElement, mVisible && mStartCaretVisible);

  dom::Element* endElement = mPresShell->GetSelectionCaretsEndElement();
  SetElementVisibility(endElement, mVisible && mEndCaretVisible);

  // We must call SetHasTouchCaret() in order to get APZC to wait until the
  // event has been round-tripped and check whether it has been handled,
  // otherwise B2G will end up panning the document when the user tries to drag
  // selection caret.
  mPresShell->SetMayHaveTouchCaret(mVisible);
}

void
SelectionCarets::SetStartFrameVisibility(bool aVisible)
{
  mStartCaretVisible = aVisible;
  SELECTIONCARETS_LOG("Set start frame visibility %s",
                      (mStartCaretVisible ? "shown" : "hidden"));

  dom::Element* element = mPresShell->GetSelectionCaretsStartElement();
  SetElementVisibility(element, mVisible && mStartCaretVisible);
}

void
SelectionCarets::SetEndFrameVisibility(bool aVisible)
{
  mEndCaretVisible = aVisible;
  SELECTIONCARETS_LOG("Set end frame visibility %s",
                      (mEndCaretVisible ? "shown" : "hidden"));

  dom::Element* element = mPresShell->GetSelectionCaretsEndElement();
  SetElementVisibility(element, mVisible && mEndCaretVisible);
}

void
SelectionCarets::SetTilted(bool aIsTilt)
{
  dom::Element* startElement = mPresShell->GetSelectionCaretsStartElement();
  dom::Element* endElement = mPresShell->GetSelectionCaretsEndElement();

  if (!startElement || !endElement) {
    return;
  }

  SELECTIONCARETS_LOG("Set tilted selection carets %s",
                      (aIsTilt ? "enabled" : "disabled"));

  ErrorResult err;
  startElement->ClassList()->Toggle(NS_LITERAL_STRING("tilt"),
                                       dom::Optional<bool>(aIsTilt), err);

  endElement->ClassList()->Toggle(NS_LITERAL_STRING("tilt"),
                                     dom::Optional<bool>(aIsTilt), err);
}

static void
SetCaretDirection(dom::Element* aElement, bool aIsRight)
{
  MOZ_ASSERT(aElement);

  ErrorResult err;
  if (aIsRight) {
    aElement->ClassList()->Add(NS_LITERAL_STRING("moz-selectioncaret-right"), err);
    aElement->ClassList()->Remove(NS_LITERAL_STRING("moz-selectioncaret-left"), err);
  } else {
    aElement->ClassList()->Add(NS_LITERAL_STRING("moz-selectioncaret-left"), err);
    aElement->ClassList()->Remove(NS_LITERAL_STRING("moz-selectioncaret-right"), err);
  }
}

static nsIFrame*
FindFirstNodeWithFrame(nsIDocument* aDocument,
                       nsRange* aRange,
                       nsFrameSelection* aFrameSelection,
                       bool aBackward,
                       int& aOutOffset)
{
  if (!aDocument || !aRange || !aFrameSelection) {
    return nullptr;
  }

  nsCOMPtr<nsINode> startNode =
    do_QueryInterface(aBackward ? aRange->GetEndParent() : aRange->GetStartParent());
  nsCOMPtr<nsINode> endNode =
    do_QueryInterface(aBackward ? aRange->GetStartParent() : aRange->GetEndParent());
  int32_t offset = aBackward ? aRange->EndOffset() : aRange->StartOffset();

  nsCOMPtr<nsIContent> startContent = do_QueryInterface(startNode);
  CaretAssociationHint hintStart =
    aBackward ? CARET_ASSOCIATE_BEFORE : CARET_ASSOCIATE_AFTER;
  nsIFrame* startFrame = aFrameSelection->GetFrameForNodeOffset(startContent,
                                                                offset,
                                                                hintStart,
                                                                &aOutOffset);

  if (startFrame) {
    return startFrame;
  }

  ErrorResult err;
  nsRefPtr<dom::TreeWalker> walker =
    aDocument->CreateTreeWalker(*startNode,
                                nsIDOMNodeFilter::SHOW_ALL,
                                nullptr,
                                err);

  if (!walker) {
    return nullptr;
  }

  startFrame = startContent ? startContent->GetPrimaryFrame() : nullptr;
  while (!startFrame && startNode != endNode) {
    if (aBackward) {
      startNode = walker->PreviousNode(err);
    } else {
      startNode = walker->NextNode(err);
    }

    if (!startNode) {
      break;
    }

    startContent = do_QueryInterface(startNode);
    startFrame = startContent ? startContent->GetPrimaryFrame() : nullptr;
  }
  return startFrame;
}

void
SelectionCarets::UpdateSelectionCarets()
{
  if (!mPresShell) {
    return;
  }

  nsRefPtr<dom::Selection> selection = GetSelection();
  if (!selection) {
    SELECTIONCARETS_LOG("Cannot get selection!");
    SetVisibility(false);
    return;
  }

  if (selection->IsCollapsed()) {
    SELECTIONCARETS_LOG("Selection is collapsed!");
    SetVisibility(false);
    return;
  }

  int32_t rangeCount = selection->GetRangeCount();
  nsRefPtr<nsRange> firstRange = selection->GetRangeAt(0);
  nsRefPtr<nsRange> lastRange = selection->GetRangeAt(rangeCount - 1);

  nsIFrame* canvasFrame = mPresShell->GetCanvasFrame();
  nsIFrame* rootFrame = mPresShell->GetRootFrame();

  if (!canvasFrame || !rootFrame) {
    SetVisibility(false);
    return;
  }

  // Check start and end frame is rtl or ltr text
  nsRefPtr<nsFrameSelection> fs = GetFrameSelection();
  int32_t startOffset;
  nsIFrame* startFrame = FindFirstNodeWithFrame(mPresShell->GetDocument(),
                                                firstRange, fs, false, startOffset);

  int32_t endOffset;
  nsIFrame* endFrame = FindFirstNodeWithFrame(mPresShell->GetDocument(),
                                              lastRange, fs, true, endOffset);

  if (!startFrame || !endFrame) {
    SetVisibility(false);
    return;
  }

  // If frame isn't editable and we don't support non-editable fields, bail
  // out.
  if (!kSupportNonEditableFields &&
      (!startFrame->GetContent()->IsEditable() ||
       !endFrame->GetContent()->IsEditable())) {
    return;
  }

  // Check if startFrame is after endFrame.
  if (nsLayoutUtils::CompareTreePosition(startFrame, endFrame) > 0) {
    SetVisibility(false);
    return;
  }

  mPresShell->FlushPendingNotifications(Flush_Layout);

  // If the selection is not visible, we should dispatch a event.
  nsIFrame* commonAncestorFrame =
    nsLayoutUtils::FindNearestCommonAncestorFrame(startFrame, endFrame);

  nsRect selectionRectInRootFrame = GetSelectionBoundingRect(selection);
  nsRect selectionRectInCommonAncestorFrame = selectionRectInRootFrame;
  nsLayoutUtils::TransformRect(rootFrame, commonAncestorFrame,
                               selectionRectInCommonAncestorFrame);

  mSelectionVisibleInScrollFrames =
    nsLayoutUtils::IsRectVisibleInScrollFrames(commonAncestorFrame,
                                               selectionRectInCommonAncestorFrame);
  SELECTIONCARETS_LOG("Selection visibility %s",
                      (mSelectionVisibleInScrollFrames ? "shown" : "hidden"));


  nsRect firstRectInStartFrame =
    nsCaret::GetGeometryForFrame(startFrame, startOffset, nullptr);
  nsRect lastRectInEndFrame =
    nsCaret::GetGeometryForFrame(endFrame, endOffset, nullptr);

  bool startFrameVisible =
    nsLayoutUtils::IsRectVisibleInScrollFrames(startFrame, firstRectInStartFrame);
  bool endFrameVisible =
    nsLayoutUtils::IsRectVisibleInScrollFrames(endFrame, lastRectInEndFrame);

  nsRect firstRectInCanvasFrame = firstRectInStartFrame;
  nsRect lastRectInCanvasFrame = lastRectInEndFrame;
  nsLayoutUtils::TransformRect(startFrame, canvasFrame, firstRectInCanvasFrame);
  nsLayoutUtils::TransformRect(endFrame, canvasFrame, lastRectInCanvasFrame);

  SetStartFrameVisibility(startFrameVisible);
  SetEndFrameVisibility(endFrameVisible);

  SetStartFramePos(firstRectInCanvasFrame.BottomLeft());
  SetEndFramePos(lastRectInCanvasFrame.BottomRight());
  SetVisibility(true);

  nsRect rectStart = GetStartFrameRect();
  nsRect rectEnd = GetEndFrameRect();
  bool isTilt = rectStart.Intersects(rectEnd);
  if (isTilt) {
    SetCaretDirection(mPresShell->GetSelectionCaretsStartElement(), rectStart.x > rectEnd.x);
    SetCaretDirection(mPresShell->GetSelectionCaretsEndElement(), rectStart.x <= rectEnd.x);
  }
  SetTilted(isTilt);
}

nsresult
SelectionCarets::SelectWord()
{
  if (!mPresShell) {
    return NS_OK;
  }

  nsIFrame* rootFrame = mPresShell->GetRootFrame();
  if (!rootFrame) {
    return NS_OK;
  }

  // Find content offsets for mouse down point
  nsIFrame *ptFrame = nsLayoutUtils::GetFrameForPoint(rootFrame, mDownPoint,
    nsLayoutUtils::IGNORE_PAINT_SUPPRESSION | nsLayoutUtils::IGNORE_CROSS_DOC);
  if (!ptFrame) {
    return NS_OK;
  }

  // If frame isn't editable and we don't support non-editable fields, bail
  // out.
  if (!kSupportNonEditableFields && !ptFrame->GetContent()->IsEditable()) {
    return NS_OK;
  }

  bool selectable;
  ptFrame->IsSelectable(&selectable, nullptr);
  if (!selectable) {
    return NS_OK;
  }

  nsPoint ptInFrame = mDownPoint;
  nsLayoutUtils::TransformPoint(rootFrame, ptFrame, ptInFrame);

  // If target frame is editable, we should move focus to targe frame. If
  // target frame isn't editable and our focus content is editable, we should
  // clear focus.
  nsFocusManager* fm = nsFocusManager::GetFocusManager();
  nsIContent* editingHost = ptFrame->GetContent()->GetEditingHost();
  if (editingHost) {
    nsCOMPtr<nsIDOMElement> elt = do_QueryInterface(editingHost->GetParent());
    if (elt) {
      fm->SetFocus(elt, 0);
    }
  } else {
    nsIContent* focusedContent = GetFocusedContent();
    if (focusedContent && focusedContent->GetTextEditorRootContent()) {
      nsIDOMWindow* win = mPresShell->GetDocument()->GetWindow();
      if (win) {
        fm->ClearFocus(win);
      }
    }
  }

  SetSelectionDragState(true);
  nsFrame* frame = static_cast<nsFrame*>(ptFrame);
  nsresult rs = frame->SelectByTypeAtPoint(mPresShell->GetPresContext(), ptInFrame,
                                           eSelectWord, eSelectWord, 0);

#ifdef DEBUG_FRAME_DUMP
  nsCString frameTag;
  frame->ListTag(frameTag);
  SELECTIONCARETS_LOG("Frame=%s, ptInFrame=(%d, %d)", frameTag.get(),
                      ptInFrame.x, ptInFrame.y);
#endif

  SetSelectionDragState(false);

  // Clear maintain selection otherwise we cannot select less than a word
  nsRefPtr<nsFrameSelection> fs = GetFrameSelection();
  fs->MaintainSelection();
  return rs;
}

/*
 * If we're dragging start caret, we do not want to drag over previous
 * character of end caret. Same as end caret. So we check if content offset
 * exceed previous/next character of end/start caret base on aDragMode.
 */
static bool
CompareRangeWithContentOffset(nsRange* aRange,
                              nsFrameSelection* aSelection,
                              nsIFrame::ContentOffsets& aOffsets,
                              SelectionCarets::DragMode aDragMode)
{
  MOZ_ASSERT(aDragMode != SelectionCarets::NONE);
  nsINode* node = nullptr;
  int32_t nodeOffset = 0;
  CaretAssociationHint hint;
  nsDirection dir;

  if (aDragMode == SelectionCarets::START_FRAME) {
    // Check previous character of end node offset
    node = aRange->GetEndParent();
    nodeOffset = aRange->EndOffset();
    hint = CARET_ASSOCIATE_BEFORE;
    dir = eDirPrevious;
  } else {
    // Check next character of start node offset
    node = aRange->GetStartParent();
    nodeOffset = aRange->StartOffset();
    hint =  CARET_ASSOCIATE_AFTER;
    dir = eDirNext;
  }
  nsCOMPtr<nsIContent> content = do_QueryInterface(node);

  int32_t offset = 0;
  nsIFrame* theFrame =
    aSelection->GetFrameForNodeOffset(content, nodeOffset, hint, &offset);

  if (!theFrame) {
    return false;
  }

  // Move one character forward/backward from point and get offset
  nsPeekOffsetStruct pos(eSelectCluster,
                         dir,
                         offset,
                         nsPoint(0, 0),
                         true,
                         true,  //limit on scrolled views
                         false,
                         false);
  nsresult rv = theFrame->PeekOffset(&pos);
  if (NS_FAILED(rv)) {
    pos.mResultContent = content;
    pos.mContentOffset = nodeOffset;
  }

  // Compare with current point
  int32_t result = nsContentUtils::ComparePoints(aOffsets.content,
                                                 aOffsets.StartOffset(),
                                                 pos.mResultContent,
                                                 pos.mContentOffset);
  if ((aDragMode == SelectionCarets::START_FRAME && result == 1) ||
      (aDragMode == SelectionCarets::END_FRAME && result == -1)) {
    aOffsets.content = pos.mResultContent;
    aOffsets.offset = pos.mContentOffset;
    aOffsets.secondaryOffset = pos.mContentOffset;
  }

  return true;
}

nsEventStatus
SelectionCarets::DragSelection(const nsPoint &movePoint)
{
  nsIFrame* rootFrame = mPresShell->GetRootFrame();
  if (!rootFrame) {
    return nsEventStatus_eConsumeNoDefault;
  }

  // Find out which content we point to
  nsIFrame *ptFrame = nsLayoutUtils::GetFrameForPoint(rootFrame, movePoint,
    nsLayoutUtils::IGNORE_PAINT_SUPPRESSION | nsLayoutUtils::IGNORE_CROSS_DOC);
  if (!ptFrame) {
    return nsEventStatus_eConsumeNoDefault;
  }

  nsRefPtr<nsFrameSelection> fs = GetFrameSelection();

  nsresult result;
  nsIFrame *newFrame = nullptr;
  nsPoint newPoint;
  nsPoint ptInFrame = movePoint;
  nsLayoutUtils::TransformPoint(rootFrame, ptFrame, ptInFrame);
  result = fs->ConstrainFrameAndPointToAnchorSubtree(ptFrame, ptInFrame, &newFrame, newPoint);
  if (NS_FAILED(result) || !newFrame) {
    return nsEventStatus_eConsumeNoDefault;
  }

  bool selectable;
  newFrame->IsSelectable(&selectable, nullptr);
  if (!selectable) {
    return nsEventStatus_eConsumeNoDefault;
  }

  nsFrame::ContentOffsets offsets =
    newFrame->GetContentOffsetsFromPoint(newPoint);
  if (!offsets.content) {
    return nsEventStatus_eConsumeNoDefault;
  }

  nsRefPtr<dom::Selection> selection = GetSelection();
  int32_t rangeCount = selection->GetRangeCount();
  if (rangeCount <= 0) {
    return nsEventStatus_eConsumeNoDefault;
  }

  nsRefPtr<nsRange> range = mDragMode == START_FRAME ?
    selection->GetRangeAt(0) : selection->GetRangeAt(rangeCount - 1);
  if (!CompareRangeWithContentOffset(range, fs, offsets, mDragMode)) {
    return nsEventStatus_eConsumeNoDefault;
  }

  nsIFrame* anchorFrame;
  selection->GetPrimaryFrameForAnchorNode(&anchorFrame);
  if (!anchorFrame) {
    return nsEventStatus_eConsumeNoDefault;
  }

  // Move caret postion.
  nsIFrame *scrollable =
    nsLayoutUtils::GetClosestFrameOfType(anchorFrame, nsGkAtoms::scrollFrame);
  nsWeakFrame weakScrollable = scrollable;
  fs->HandleClick(offsets.content, offsets.StartOffset(),
                  offsets.EndOffset(),
                  true,
                  false,
                  offsets.associate);
  if (!weakScrollable.IsAlive()) {
    return nsEventStatus_eConsumeNoDefault;
  }

  // Scroll scrolled frame.
  nsIScrollableFrame *saf = do_QueryFrame(scrollable);
  nsIFrame *capturingFrame = saf->GetScrolledFrame();
  nsPoint ptInScrolled = movePoint;
  nsLayoutUtils::TransformPoint(rootFrame, capturingFrame, ptInScrolled);
  fs->StartAutoScrollTimer(capturingFrame, ptInScrolled, TouchCaret::sAutoScrollTimerDelay);
  UpdateSelectionCarets();
  return nsEventStatus_eConsumeNoDefault;
}

nscoord
SelectionCarets::GetCaretYCenterPosition()
{
  nsIFrame* rootFrame = mPresShell->GetRootFrame();

  if (!rootFrame) {
    return 0;
  }

  nsRefPtr<dom::Selection> selection = GetSelection();
  int32_t rangeCount = selection->GetRangeCount();
  if (rangeCount <= 0) {
    return 0;
  }

  nsRefPtr<nsFrameSelection> fs = GetFrameSelection();

  MOZ_ASSERT(mDragMode != NONE);
  nsCOMPtr<nsIContent> node;
  uint32_t nodeOffset;
  if (mDragMode == START_FRAME) {
    nsRefPtr<nsRange> range = selection->GetRangeAt(0);
    node = do_QueryInterface(range->GetStartParent());
    nodeOffset = range->StartOffset();
  } else {
    nsRefPtr<nsRange> range = selection->GetRangeAt(rangeCount - 1);
    node = do_QueryInterface(range->GetEndParent());
    nodeOffset = range->EndOffset();
  }

  int32_t offset;
  CaretAssociationHint hint =
    mDragMode == START_FRAME ? CARET_ASSOCIATE_AFTER : CARET_ASSOCIATE_BEFORE;
  nsIFrame* theFrame =
    fs->GetFrameForNodeOffset(node, nodeOffset, hint, &offset);

  if (!theFrame) {
    return 0;
  }
  nsRect frameRect = theFrame->GetRectRelativeToSelf();
  nsLayoutUtils::TransformRect(theFrame, rootFrame, frameRect);
  return frameRect.Center().y;
}

void
SelectionCarets::SetSelectionDragState(bool aState)
{
  nsRefPtr<nsFrameSelection> fs = GetFrameSelection();
  fs->SetDragState(aState);
}

void
SelectionCarets::SetSelectionDirection(bool aForward)
{
  nsRefPtr<dom::Selection> selection = GetSelection();
  selection->SetDirection(aForward ? eDirNext : eDirPrevious);
}

static void
SetFramePos(dom::Element* aElement, const nsPoint& aPosition)
{
  if (!aElement) {
    return;
  }

  nsAutoString styleStr;
  styleStr.AppendLiteral("left: ");
  styleStr.AppendFloat(nsPresContext::AppUnitsToFloatCSSPixels(aPosition.x));
  styleStr.AppendLiteral("px; top: ");
  styleStr.AppendFloat(nsPresContext::AppUnitsToFloatCSSPixels(aPosition.y));
  styleStr.AppendLiteral("px;");

  SELECTIONCARETS_LOG_STATIC("Set style: %s",
                             NS_ConvertUTF16toUTF8(styleStr).get());

  aElement->SetAttr(kNameSpaceID_None, nsGkAtoms::style, styleStr, true);
}

void
SelectionCarets::SetStartFramePos(const nsPoint& aPosition)
{
  SELECTIONCARETS_LOG("x=%d, y=%d", aPosition.x, aPosition.y);
  SetFramePos(mPresShell->GetSelectionCaretsStartElement(), aPosition);
}

void
SelectionCarets::SetEndFramePos(const nsPoint& aPosition)
{
  SELECTIONCARETS_LOG("x=%d, y=%d", aPosition.y, aPosition.y);
  SetFramePos(mPresShell->GetSelectionCaretsEndElement(), aPosition);
}

bool
SelectionCarets::IsOnStartFrameInner(const nsPoint& aPosition)
{
  return mVisible &&
    nsLayoutUtils::ContainsPoint(GetStartFrameRectInner(), aPosition,
                                 SelectionCaretsInflateSize());
}

bool
SelectionCarets::IsOnEndFrameInner(const nsPoint& aPosition)
{
  return mVisible &&
    nsLayoutUtils::ContainsPoint(GetEndFrameRectInner(), aPosition,
                                 SelectionCaretsInflateSize());
}

nsRect
SelectionCarets::GetStartFrameRect()
{
  dom::Element* element = mPresShell->GetSelectionCaretsStartElement();
  nsIFrame* rootFrame = mPresShell->GetRootFrame();
  return nsLayoutUtils::GetRectRelativeToFrame(element, rootFrame);
}

nsRect
SelectionCarets::GetEndFrameRect()
{
  dom::Element* element = mPresShell->GetSelectionCaretsEndElement();
  nsIFrame* rootFrame = mPresShell->GetRootFrame();
  return nsLayoutUtils::GetRectRelativeToFrame(element, rootFrame);
}

nsRect
SelectionCarets::GetStartFrameRectInner()
{
  dom::Element* element = mPresShell->GetSelectionCaretsStartElement();
  dom::Element* childElement = element->GetFirstElementChild();
  nsIFrame* rootFrame = mPresShell->GetRootFrame();
  return nsLayoutUtils::GetRectRelativeToFrame(childElement, rootFrame);
}

nsRect
SelectionCarets::GetEndFrameRectInner()
{
  dom::Element* element = mPresShell->GetSelectionCaretsEndElement();
  dom::Element* childElement = element->GetFirstElementChild();
  nsIFrame* rootFrame = mPresShell->GetRootFrame();
  return nsLayoutUtils::GetRectRelativeToFrame(childElement, rootFrame);
}

nsIContent*
SelectionCarets::GetFocusedContent()
{
  nsFocusManager* fm = nsFocusManager::GetFocusManager();
  if (fm) {
    return fm->GetFocusedContent();
  }

  return nullptr;
}

Selection*
SelectionCarets::GetSelection()
{
  nsRefPtr<nsFrameSelection> fs = GetFrameSelection();
  if (fs) {
    return fs->GetSelection(nsISelectionController::SELECTION_NORMAL);
  }
  return nullptr;
}

already_AddRefed<nsFrameSelection>
SelectionCarets::GetFrameSelection()
{
  nsIContent* focusNode = GetFocusedContent();
  if (focusNode) {
    nsIFrame* focusFrame = focusNode->GetPrimaryFrame();
    if (!focusFrame) {
      return nullptr;
    }

    // Prevent us from touching the nsFrameSelection associated to other
    // PresShell.
    nsRefPtr<nsFrameSelection> fs = focusFrame->GetFrameSelection();
    if (!fs || fs->GetShell() != mPresShell) {
      return nullptr;
    }

    return fs.forget();
  } else {
    return mPresShell->FrameSelection();
  }
}

static dom::Sequence<SelectionState>
GetSelectionStates(int16_t aReason)
{
  dom::Sequence<SelectionState> states;
  if (aReason & nsISelectionListener::DRAG_REASON) {
    states.AppendElement(SelectionState::Drag);
  }
  if (aReason & nsISelectionListener::MOUSEDOWN_REASON) {
    states.AppendElement(SelectionState::Mousedown);
  }
  if (aReason & nsISelectionListener::MOUSEUP_REASON) {
    states.AppendElement(SelectionState::Mouseup);
  }
  if (aReason & nsISelectionListener::KEYPRESS_REASON) {
    states.AppendElement(SelectionState::Keypress);
  }
  if (aReason & nsISelectionListener::SELECTALL_REASON) {
    states.AppendElement(SelectionState::Selectall);
  }
  if (aReason & nsISelectionListener::COLLAPSETOSTART_REASON) {
    states.AppendElement(SelectionState::Collapsetostart);
  }
  if (aReason & nsISelectionListener::COLLAPSETOEND_REASON) {
    states.AppendElement(SelectionState::Collapsetoend);
  }
  return states;
}

nsRect
SelectionCarets::GetSelectionBoundingRect(Selection* aSel)
{
  nsRect res;
  // Bounding client rect may be empty after calling GetBoundingClientRect
  // when range is collapsed. So we get caret's rect when range is
  // collapsed.
  if (aSel->IsCollapsed()) {
    nsIFrame* frame = nsCaret::GetGeometry(aSel, &res);
    if (frame) {
      nsIFrame* relativeTo =
        nsLayoutUtils::GetContainingBlockForClientRect(frame);
      res = nsLayoutUtils::TransformFrameRectToAncestor(frame, res, relativeTo);
    }
  } else {
    int32_t rangeCount = aSel->GetRangeCount();
    nsLayoutUtils::RectAccumulator accumulator;
    for (int32_t idx = 0; idx < rangeCount; ++idx) {
      nsRange* range = aSel->GetRangeAt(idx);
      nsRange::CollectClientRects(&accumulator, range,
                                  range->GetStartParent(), range->StartOffset(),
                                  range->GetEndParent(), range->EndOffset(),
                                  true, false);
    }
    res = accumulator.mResultRect.IsEmpty() ? accumulator.mFirstRect :
      accumulator.mResultRect;
  }

  return res;
}

void
SelectionCarets::DispatchSelectionStateChangedEvent(Selection* aSelection,
                                                    SelectionState aState)
{
  dom::Sequence<SelectionState> state;
  state.AppendElement(aState);
  DispatchSelectionStateChangedEvent(aSelection, state);
}

void
SelectionCarets::DispatchSelectionStateChangedEvent(Selection* aSelection,
                                                    const Sequence<SelectionState>& aStates)
{
  nsIDocument* doc = mPresShell->GetDocument();

  MOZ_ASSERT(doc);

  SelectionStateChangedEventInit init;
  init.mBubbles = true;

  if (aSelection) {
    // XXX: Do we need to flush layout?
    mPresShell->FlushPendingNotifications(Flush_Layout);
    nsRect rect = GetSelectionBoundingRect(aSelection);
    nsRefPtr<DOMRect>domRect = new DOMRect(ToSupports(doc));

    domRect->SetLayoutRect(rect);
    init.mBoundingClientRect = domRect;
    init.mVisible = mSelectionVisibleInScrollFrames;

    aSelection->Stringify(init.mSelectedText);
  }
  init.mStates = aStates;

  nsRefPtr<SelectionStateChangedEvent> event =
    SelectionStateChangedEvent::Constructor(doc, NS_LITERAL_STRING("mozselectionstatechanged"), init);

  event->SetTrusted(true);
  event->GetInternalNSEvent()->mFlags.mOnlyChromeDispatch = true;
  bool ret;
  doc->DispatchEvent(event, &ret);
}

void
SelectionCarets::NotifyBlur()
{
  SetVisibility(false);
  DispatchSelectionStateChangedEvent(nullptr, SelectionState::Blur);
}

nsresult
SelectionCarets::NotifySelectionChanged(nsIDOMDocument* aDoc,
                                        nsISelection* aSel,
                                        int16_t aReason)
{
  SELECTIONCARETS_LOG("aSel (%p), Reason=%d", aSel, aReason);
  if (!aReason || (aReason & (nsISelectionListener::DRAG_REASON |
                              nsISelectionListener::KEYPRESS_REASON |
                              nsISelectionListener::MOUSEDOWN_REASON))) {
    SetVisibility(false);
  } else {
    UpdateSelectionCarets();
  }

  DispatchSelectionStateChangedEvent(static_cast<Selection*>(aSel),
                                     GetSelectionStates(aReason));
  return NS_OK;
}

static void
DispatchScrollViewChangeEvent(nsIPresShell *aPresShell, const dom::ScrollState aState, const mozilla::CSSIntPoint aScrollPos)
{
  nsCOMPtr<nsIDocument> doc = aPresShell->GetDocument();
  if (doc) {
    bool ret;
    ScrollViewChangeEventInit detail;
    detail.mBubbles = true;
    detail.mCancelable = false;
    detail.mState = aState;
    detail.mScrollX = aScrollPos.x;
    detail.mScrollY = aScrollPos.y;
    nsRefPtr<ScrollViewChangeEvent> event =
      ScrollViewChangeEvent::Constructor(doc, NS_LITERAL_STRING("scrollviewchange"), detail);

    event->SetTrusted(true);
    event->GetInternalNSEvent()->mFlags.mOnlyChromeDispatch = true;
    doc->DispatchEvent(event, &ret);
  }
}

void
SelectionCarets::AsyncPanZoomStarted(const mozilla::CSSIntPoint aScrollPos)
{
  SetVisibility(false);

  SELECTIONCARETS_LOG("Dispatch scroll started with position x=%d, y=%d",
                      aScrollPos.x, aScrollPos.y);
  DispatchScrollViewChangeEvent(mPresShell, dom::ScrollState::Started, aScrollPos);
}

void
SelectionCarets::AsyncPanZoomStopped(const mozilla::CSSIntPoint aScrollPos)
{
  SELECTIONCARETS_LOG("Update selection carets after APZ is stopped!");
  UpdateSelectionCarets();

  // SelectionStateChangedEvent should be dispatched before ScrollViewChangeEvent.
  DispatchSelectionStateChangedEvent(GetSelection(),
                                     SelectionState::Updateposition);

  SELECTIONCARETS_LOG("Dispatch scroll stopped with position x=%d, y=%d",
                      aScrollPos.x, aScrollPos.y);

  DispatchScrollViewChangeEvent(mPresShell, dom::ScrollState::Stopped, aScrollPos);
}

void
SelectionCarets::ScrollPositionChanged()
{
  if (!mAsyncPanZoomEnabled && mVisible) {
    SetVisibility(false);
    //TODO: handling scrolling for selection bubble when APZ is off

    SELECTIONCARETS_LOG("Launch scroll end detector");
    LaunchScrollEndDetector();
  }
}

void
SelectionCarets::LaunchLongTapDetector()
{
  if (mAsyncPanZoomEnabled) {
    return;
  }

  if (!mLongTapDetectorTimer) {
    mLongTapDetectorTimer = do_CreateInstance("@mozilla.org/timer;1");
  }

  MOZ_ASSERT(mLongTapDetectorTimer);
  CancelLongTapDetector();
  int32_t longTapDelay = gfxPrefs::UiClickHoldContextMenusDelay();

  SELECTIONCARETS_LOG("Will fire long tap after %d ms", longTapDelay);
  mLongTapDetectorTimer->InitWithFuncCallback(FireLongTap,
                                              this,
                                              longTapDelay,
                                              nsITimer::TYPE_ONE_SHOT);
}

void
SelectionCarets::CancelLongTapDetector()
{
  if (mAsyncPanZoomEnabled) {
    return;
  }

  if (!mLongTapDetectorTimer) {
    return;
  }

  SELECTIONCARETS_LOG("Cancel long tap detector!");
  mLongTapDetectorTimer->Cancel();
}

/* static */void
SelectionCarets::FireLongTap(nsITimer* aTimer, void* aSelectionCarets)
{
  nsRefPtr<SelectionCarets> self = static_cast<SelectionCarets*>(aSelectionCarets);
  NS_PRECONDITION(aTimer == self->mLongTapDetectorTimer,
                  "Unexpected timer");

  SELECTIONCARETS_LOG_STATIC("SelectWord from non-APZ");
  self->SelectWord();
}

void
SelectionCarets::LaunchScrollEndDetector()
{
  if (!mScrollEndDetectorTimer) {
    mScrollEndDetectorTimer = do_CreateInstance("@mozilla.org/timer;1");
  }

  MOZ_ASSERT(mScrollEndDetectorTimer);

  SELECTIONCARETS_LOG("Will fire scroll end after %d ms", kScrollEndTimerDelay);
  mScrollEndDetectorTimer->InitWithFuncCallback(FireScrollEnd,
                                                this,
                                                kScrollEndTimerDelay,
                                                nsITimer::TYPE_ONE_SHOT);
}

/* static */void
SelectionCarets::FireScrollEnd(nsITimer* aTimer, void* aSelectionCarets)
{
  nsRefPtr<SelectionCarets> self = static_cast<SelectionCarets*>(aSelectionCarets);
  NS_PRECONDITION(aTimer == self->mScrollEndDetectorTimer,
                  "Unexpected timer");

  SELECTIONCARETS_LOG_STATIC("Update selection carets!");
  self->SetVisibility(true);
  self->UpdateSelectionCarets();
  self->DispatchSelectionStateChangedEvent(self->GetSelection(),
                                           SelectionState::Updateposition);
}

NS_IMETHODIMP
SelectionCarets::Reflow(DOMHighResTimeStamp aStart, DOMHighResTimeStamp aEnd)
{
  if (mVisible) {
    SELECTIONCARETS_LOG("Update selection carets after reflow!");
    UpdateSelectionCarets();

    DispatchSelectionStateChangedEvent(GetSelection(),
                                       SelectionState::Updateposition);
  }
  return NS_OK;
}

NS_IMETHODIMP
SelectionCarets::ReflowInterruptible(DOMHighResTimeStamp aStart,
                                     DOMHighResTimeStamp aEnd)
{
  return Reflow(aStart, aEnd);
}
