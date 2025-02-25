/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil; tab-width: 8; -*- */
/* vim: set sw=2 ts=8 et tw=80 : */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "base/basictypes.h"

#include "TabParent.h"

#include "AppProcessChecker.h"
#include "mozIApplication.h"
#include "mozilla/BrowserElementParent.h"
#include "mozilla/dom/ContentParent.h"
#include "mozilla/dom/PContentPermissionRequestParent.h"
#include "mozilla/dom/indexedDB/ActorsParent.h"
#include "mozilla/plugins/PluginWidgetParent.h"
#include "mozilla/EventStateManager.h"
#include "mozilla/Hal.h"
#include "mozilla/ipc/DocumentRendererParent.h"
#include "mozilla/layers/CompositorParent.h"
#include "mozilla/layout/RenderFrameParent.h"
#include "mozilla/MouseEvents.h"
#include "mozilla/net/NeckoChild.h"
#include "mozilla/Preferences.h"
#include "mozilla/TextEvents.h"
#include "mozilla/TouchEvents.h"
#include "mozilla/unused.h"
#include "nsCOMPtr.h"
#include "nsContentPermissionHelper.h"
#include "nsContentUtils.h"
#include "nsDebug.h"
#include "nsFocusManager.h"
#include "nsFrameLoader.h"
#include "nsIContent.h"
#include "nsIDocShell.h"
#include "nsIDocShellTreeOwner.h"
#include "nsIDOMElement.h"
#include "nsIDOMEvent.h"
#include "nsIDOMWindow.h"
#include "nsIDOMWindowUtils.h"
#include "nsIInterfaceRequestorUtils.h"
#include "nsILoadInfo.h"
#include "nsIPromptFactory.h"
#include "nsIURI.h"
#include "nsIWebBrowserChrome.h"
#include "nsIWindowCreator2.h"
#include "nsIXULBrowserWindow.h"
#include "nsIXULWindow.h"
#include "nsIRemoteBrowser.h"
#include "nsViewManager.h"
#include "nsIWidget.h"
#include "nsIWindowWatcher.h"
#include "nsOpenURIInFrameParams.h"
#include "nsPIDOMWindow.h"
#include "nsPIWindowWatcher.h"
#include "nsPresShell.h"
#include "nsPrintfCString.h"
#include "nsServiceManagerUtils.h"
#include "nsThreadUtils.h"
#include "nsWindowWatcher.h"
#include "private/pprio.h"
#include "PermissionMessageUtils.h"
#include "StructuredCloneUtils.h"
#include "ColorPickerParent.h"
#include "JavaScriptParent.h"
#include "FilePickerParent.h"
#include "TabChild.h"
#include "LoadContext.h"
#include "nsNetCID.h"
#include "nsIAuthInformation.h"
#include "nsIAuthPromptCallback.h"
#include "nsAuthInformationHolder.h"
#include "nsICancelable.h"
#include "gfxPrefs.h"
#include "nsILoginManagerPrompter.h"
#include <algorithm>

using namespace mozilla::dom;
using namespace mozilla::ipc;
using namespace mozilla::layers;
using namespace mozilla::layout;
using namespace mozilla::services;
using namespace mozilla::widget;
using namespace mozilla::jsipc;

// The flags passed by the webProgress notifications are 16 bits shifted
// from the ones registered by webProgressListeners.
#define NOTIFY_FLAG_SHIFT 16

class OpenFileAndSendFDRunnable : public nsRunnable
{
    const nsString mPath;
    nsRefPtr<TabParent> mTabParent;
    nsCOMPtr<nsIEventTarget> mEventTarget;
    PRFileDesc* mFD;

public:
    OpenFileAndSendFDRunnable(const nsAString& aPath, TabParent* aTabParent)
      : mPath(aPath), mTabParent(aTabParent), mFD(nullptr)
    {
        MOZ_ASSERT(NS_IsMainThread());
        MOZ_ASSERT(!aPath.IsEmpty());
        MOZ_ASSERT(aTabParent);
    }

    void Dispatch()
    {
        MOZ_ASSERT(NS_IsMainThread());

        mEventTarget = do_GetService(NS_STREAMTRANSPORTSERVICE_CONTRACTID);
        NS_ENSURE_TRUE_VOID(mEventTarget);

        nsresult rv = mEventTarget->Dispatch(this, NS_DISPATCH_NORMAL);
        NS_ENSURE_SUCCESS_VOID(rv);
    }

private:
    ~OpenFileAndSendFDRunnable()
    {
        MOZ_ASSERT(!mFD);
    }

    // This shouldn't be called directly except by the event loop. Use Dispatch
    // to start the sequence.
    NS_IMETHOD Run()
    {
        if (NS_IsMainThread()) {
            SendResponse();
        } else if (mFD) {
            CloseFile();
        } else {
            OpenFile();
        }

        return NS_OK;
    }

    void SendResponse()
    {
        MOZ_ASSERT(NS_IsMainThread());
        MOZ_ASSERT(mTabParent);
        MOZ_ASSERT(mEventTarget);
        MOZ_ASSERT(mFD);

        nsRefPtr<TabParent> tabParent;
        mTabParent.swap(tabParent);

        using mozilla::ipc::FileDescriptor;

        FileDescriptor::PlatformHandleType handle =
            FileDescriptor::PlatformHandleType(PR_FileDesc2NativeHandle(mFD));

        // Our TabParent may have been destroyed already.  If so, don't send any
        // fds over, just go back to the IO thread and close them.
        if (!tabParent->IsDestroyed()) {
          mozilla::unused << tabParent->SendCacheFileDescriptor(mPath,
                                                                FileDescriptor(handle));
        }

        nsCOMPtr<nsIEventTarget> eventTarget;
        mEventTarget.swap(eventTarget);

        if (NS_FAILED(eventTarget->Dispatch(this, NS_DISPATCH_NORMAL))) {
            NS_WARNING("Failed to dispatch to stream transport service!");

            // It's probably safer to take the main thread IO hit here rather
            // than leak a file descriptor.
            CloseFile();
        }
    }

    void OpenFile()
    {
        MOZ_ASSERT(!NS_IsMainThread());
        MOZ_ASSERT(!mFD);

        nsCOMPtr<nsIFile> file;
        nsresult rv = NS_NewLocalFile(mPath, false, getter_AddRefs(file));
        NS_ENSURE_SUCCESS_VOID(rv);

        PRFileDesc* fd;
        rv = file->OpenNSPRFileDesc(PR_RDONLY, 0, &fd);
        NS_ENSURE_SUCCESS_VOID(rv);

        mFD = fd;

        if (NS_FAILED(NS_DispatchToMainThread(this))) {
            NS_WARNING("Failed to dispatch to main thread!");

            CloseFile();
        }
    }

    void CloseFile()
    {
        // It's possible for this to happen on the main thread if the dispatch
        // to the stream service fails after we've already opened the file so
        // we can't assert the thread we're running on.

        MOZ_ASSERT(mFD);

        PRStatus prrc;
        prrc = PR_Close(mFD);
        if (prrc != PR_SUCCESS) {
          NS_ERROR("PR_Close() failed.");
        }
        mFD = nullptr;
    }
};

namespace mozilla {
namespace dom {

TabParent* sEventCapturer;

TabParent *TabParent::mIMETabParent = nullptr;

NS_IMPL_ISUPPORTS(TabParent,
                  nsITabParent,
                  nsIAuthPromptProvider,
                  nsISecureBrowserUI,
                  nsISupportsWeakReference)

TabParent::TabParent(nsIContentParent* aManager,
                     const TabId& aTabId,
                     const TabContext& aContext,
                     uint32_t aChromeFlags)
  : TabContext(aContext)
  , mFrameElement(nullptr)
  , mIMESelectionAnchor(0)
  , mIMESelectionFocus(0)
  , mWritingMode()
  , mIMEComposing(false)
  , mIMECompositionEnding(false)
  , mIMECompositionStart(0)
  , mIMESeqno(0)
  , mIMECompositionRectOffset(0)
  , mEventCaptureDepth(0)
  , mRect(0, 0, 0, 0)
  , mDimensions(0, 0)
  , mOrientation(0)
  , mDPI(0)
  , mDefaultScale(0)
  , mShown(false)
  , mUpdatedDimensions(false)
  , mManager(aManager)
  , mMarkedDestroying(false)
  , mIsDestroyed(false)
  , mAppPackageFileDescriptorSent(false)
  , mSendOfflineStatus(true)
  , mChromeFlags(aChromeFlags)
  , mInitedByParent(false)
  , mTabId(aTabId)
{
  MOZ_ASSERT(aManager);
}

TabParent::~TabParent()
{
}

void
TabParent::SetOwnerElement(Element* aElement)
{
  mFrameElement = aElement;
  TryCacheDPIAndScale();
}

void
TabParent::GetAppType(nsAString& aOut)
{
  aOut.Truncate();
  nsCOMPtr<Element> elem = do_QueryInterface(mFrameElement);
  if (!elem) {
    return;
  }

  elem->GetAttr(kNameSpaceID_None, nsGkAtoms::mozapptype, aOut);
}

bool
TabParent::IsVisible()
{
  nsRefPtr<nsFrameLoader> frameLoader = GetFrameLoader();
  if (!frameLoader) {
    return false;
  }

  bool visible = false;
  frameLoader->GetVisible(&visible);
  return visible;
}

void
TabParent::Destroy()
{
  if (mIsDestroyed) {
    return;
  }

  // If this fails, it's most likely due to a content-process crash,
  // and auto-cleanup will kick in.  Otherwise, the child side will
  // destroy itself and send back __delete__().
  unused << SendDestroy();

  if (RenderFrameParent* frame = GetRenderFrame()) {
    frame->Destroy();
  }
  mIsDestroyed = true;

  if (XRE_GetProcessType() == GeckoProcessType_Default) {
    Manager()->AsContentParent()->NotifyTabDestroying(this);
  }
  mMarkedDestroying = true;
}

bool
TabParent::Recv__delete__()
{
  if (XRE_GetProcessType() == GeckoProcessType_Default) {
    Manager()->AsContentParent()->NotifyTabDestroyed(this, mMarkedDestroying);
    ContentParent::DeallocateTabId(mTabId,
                                   Manager()->AsContentParent()->ChildID());
  }
  else {
    ContentParent::DeallocateTabId(mTabId, ContentParentId(0));
  }

  return true;
}

void
TabParent::ActorDestroy(ActorDestroyReason why)
{
  if (sEventCapturer == this) {
    sEventCapturer = nullptr;
  }
  if (mIMETabParent == this) {
    mIMETabParent = nullptr;
  }
  nsRefPtr<nsFrameLoader> frameLoader = GetFrameLoader();
  nsCOMPtr<nsIObserverService> os = services::GetObserverService();
  nsRefPtr<nsFrameMessageManager> fmm;
  if (frameLoader) {
    fmm = frameLoader->GetFrameMessageManager();
    nsCOMPtr<Element> frameElement(mFrameElement);
    ReceiveMessage(CHILD_PROCESS_SHUTDOWN_MESSAGE, false, nullptr, nullptr,
                   nullptr);
    frameLoader->DestroyChild();

    if (why == AbnormalShutdown && os) {
      os->NotifyObservers(NS_ISUPPORTS_CAST(nsIFrameLoader*, frameLoader),
                          "oop-frameloader-crashed", nullptr);
      nsContentUtils::DispatchTrustedEvent(frameElement->OwnerDoc(), frameElement,
                                           NS_LITERAL_STRING("oop-browser-crashed"),
                                           true, true);
    }
  }

  if (os) {
    os->NotifyObservers(NS_ISUPPORTS_CAST(nsITabParent*, this), "ipc:browser-destroyed", nullptr);
  }
  if (fmm) {
    fmm->Disconnect();
  }
}

bool
TabParent::RecvMoveFocus(const bool& aForward)
{
  nsCOMPtr<nsIFocusManager> fm = do_GetService(FOCUSMANAGER_CONTRACTID);
  if (fm) {
    nsCOMPtr<nsIDOMElement> dummy;
    uint32_t type = aForward ? uint32_t(nsIFocusManager::MOVEFOCUS_FORWARD)
                             : uint32_t(nsIFocusManager::MOVEFOCUS_BACKWARD);
    nsCOMPtr<nsIDOMElement> frame = do_QueryInterface(mFrameElement);
    fm->MoveFocus(nullptr, frame, type, nsIFocusManager::FLAG_BYKEY,
                  getter_AddRefs(dummy));
  }
  return true;
}

bool
TabParent::RecvEvent(const RemoteDOMEvent& aEvent)
{
  nsCOMPtr<nsIDOMEvent> event = do_QueryInterface(aEvent.mEvent);
  NS_ENSURE_TRUE(event, true);

  nsCOMPtr<mozilla::dom::EventTarget> target = do_QueryInterface(mFrameElement);
  NS_ENSURE_TRUE(target, true);

  event->SetOwner(target);

  bool dummy;
  target->DispatchEvent(event, &dummy);
  return true;
}

bool
TabParent::AnswerCreateWindow(const uint32_t& aChromeFlags,
                              const bool& aCalledFromJS,
                              const bool& aPositionSpecified,
                              const bool& aSizeSpecified,
                              const nsString& aURI,
                              const nsString& aName,
                              const nsString& aFeatures,
                              const nsString& aBaseURI,
                              bool* aWindowIsNew,
                              PBrowserParent** aRetVal)
{
  if (IsBrowserOrApp()) {
    return false;
  }

  nsresult rv;
  nsCOMPtr<nsPIWindowWatcher> pwwatch =
    do_GetService(NS_WINDOWWATCHER_CONTRACTID, &rv);
  NS_ENSURE_SUCCESS(rv, false);

  nsCOMPtr<nsIContent> frame(do_QueryInterface(mFrameElement));
  NS_ENSURE_TRUE(frame, false);

  nsCOMPtr<nsIDOMWindow> parent = do_QueryInterface(frame->OwnerDoc()->GetWindow());
  NS_ENSURE_TRUE(parent, false);

  int32_t openLocation =
    nsWindowWatcher::GetWindowOpenLocation(parent, aChromeFlags, aCalledFromJS,
                                           aPositionSpecified, aSizeSpecified);

  MOZ_ASSERT(openLocation == nsIBrowserDOMWindow::OPEN_NEWTAB ||
             openLocation == nsIBrowserDOMWindow::OPEN_NEWWINDOW);

  *aWindowIsNew = true;

  // Opening new tabs is the easy case...
  if (openLocation == nsIBrowserDOMWindow::OPEN_NEWTAB) {
    NS_ENSURE_TRUE(mBrowserDOMWindow, false);

    bool isPrivate;
    nsCOMPtr<nsILoadContext> loadContext = GetLoadContext();
    loadContext->GetUsePrivateBrowsing(&isPrivate);

    nsCOMPtr<nsIOpenURIInFrameParams> params = new nsOpenURIInFrameParams();
    params->SetReferrer(aBaseURI);
    params->SetIsPrivate(isPrivate);

    nsCOMPtr<nsIFrameLoaderOwner> frameLoaderOwner;
    mBrowserDOMWindow->OpenURIInFrame(nullptr, params,
                                      nsIBrowserDOMWindow::OPEN_NEWTAB,
                                      nsIBrowserDOMWindow::OPEN_NEW,
                                      getter_AddRefs(frameLoaderOwner));
    NS_ENSURE_TRUE(frameLoaderOwner, false);

    nsRefPtr<nsFrameLoader> frameLoader = frameLoaderOwner->GetFrameLoader();
    NS_ENSURE_TRUE(frameLoader, false);

    *aRetVal = frameLoader->GetRemoteBrowser();
    return true;
  }

  // WindowWatcher is going to expect a valid URI to open a window
  // to. If it can't find one, it's going to attempt to figure one
  // out on its own, which is problematic because it can't access
  // the document for the remote browser we're opening. Luckily,
  // TabChild has sent us a baseURI with which we can ensure that
  // the URI we pass to WindowWatcher is valid.
  nsCOMPtr<nsIURI> baseURI;
  rv = NS_NewURI(getter_AddRefs(baseURI), aBaseURI);
  NS_ENSURE_SUCCESS(rv, false);

  nsCOMPtr<nsIURI> finalURI;
  rv = NS_NewURI(getter_AddRefs(finalURI), NS_ConvertUTF16toUTF8(aURI).get(), baseURI);
  NS_ENSURE_SUCCESS(rv, false);

  nsAutoCString finalURIString;
  finalURI->GetSpec(finalURIString);

  nsCOMPtr<nsIDOMWindow> window;

  rv = pwwatch->OpenWindow2(parent, finalURIString.get(),
                            NS_ConvertUTF16toUTF8(aName).get(),
                            NS_ConvertUTF16toUTF8(aFeatures).get(), aCalledFromJS,
                            false, false, this, nullptr, getter_AddRefs(window));
  NS_ENSURE_SUCCESS(rv, false);

  nsCOMPtr<nsPIDOMWindow> pwindow = do_QueryInterface(window);
  NS_ENSURE_TRUE(pwindow, false);

  nsRefPtr<nsIDocShell> newDocShell = pwindow->GetDocShell();
  NS_ENSURE_TRUE(newDocShell, false);

  nsCOMPtr<nsITabParent> newRemoteTab = newDocShell->GetOpenedRemote();
  NS_ENSURE_TRUE(newRemoteTab, false);

  *aRetVal = static_cast<TabParent*>(newRemoteTab.get());
  return true;
}

void
TabParent::LoadURL(nsIURI* aURI)
{
    MOZ_ASSERT(aURI);

    if (mIsDestroyed) {
        return;
    }

    nsCString spec;
    aURI->GetSpec(spec);

    if (!mShown) {
        NS_WARNING(nsPrintfCString("TabParent::LoadURL(%s) called before "
                                   "Show(). Ignoring LoadURL.\n",
                                   spec.get()).get());
        return;
    }

    uint32_t appId = OwnOrContainingAppId();
    if (mSendOfflineStatus && NS_IsAppOffline(appId)) {
      // If the app is offline in the parent process
      // pass that state to the child process as well
      unused << SendAppOfflineStatus(appId, true);
    }
    mSendOfflineStatus = false;

    unused << SendLoadURL(spec);

    // If this app is a packaged app then we can speed startup by sending over
    // the file descriptor for the "application.zip" file that it will
    // invariably request. Only do this once.
    if (!mAppPackageFileDescriptorSent) {
        mAppPackageFileDescriptorSent = true;

        nsCOMPtr<mozIApplication> app = GetOwnOrContainingApp();
        if (app) {
            nsString manifestURL;
            nsresult rv = app->GetManifestURL(manifestURL);
            NS_ENSURE_SUCCESS_VOID(rv);

            if (StringBeginsWith(manifestURL, NS_LITERAL_STRING("app:"))) {
                nsString basePath;
                rv = app->GetBasePath(basePath);
                NS_ENSURE_SUCCESS_VOID(rv);

                nsString appId;
                rv = app->GetId(appId);
                NS_ENSURE_SUCCESS_VOID(rv);

                nsCOMPtr<nsIFile> packageFile;
                rv = NS_NewLocalFile(basePath, false,
                                     getter_AddRefs(packageFile));
                NS_ENSURE_SUCCESS_VOID(rv);

                rv = packageFile->Append(appId);
                NS_ENSURE_SUCCESS_VOID(rv);

                rv = packageFile->Append(NS_LITERAL_STRING("application.zip"));
                NS_ENSURE_SUCCESS_VOID(rv);

                nsString path;
                rv = packageFile->GetPath(path);
                NS_ENSURE_SUCCESS_VOID(rv);

                nsRefPtr<OpenFileAndSendFDRunnable> openFileRunnable =
                    new OpenFileAndSendFDRunnable(path, this);
                openFileRunnable->Dispatch();
            }
        }
    }
}

void
TabParent::Show(const nsIntSize& size)
{
    // sigh
    mShown = true;
    mDimensions = size;
    if (mIsDestroyed) {
        return;
    }

    ScrollingBehavior scrolling = UseAsyncPanZoom() ? ASYNC_PAN_ZOOM : DEFAULT_SCROLLING;
    TextureFactoryIdentifier textureFactoryIdentifier;
    uint64_t layersId = 0;
    bool success = false;
    RenderFrameParent* renderFrame = nullptr;
    // If TabParent is initialized by parent side then the RenderFrame must also
    // be created here. If TabParent is initialized by child side,
    // child side will create RenderFrame.
    MOZ_ASSERT(!GetRenderFrame());
    if (IsInitedByParent()) {
        nsRefPtr<nsFrameLoader> frameLoader = GetFrameLoader();
        if (frameLoader) {
          renderFrame =
              new RenderFrameParent(frameLoader,
                                    scrolling,
                                    &textureFactoryIdentifier,
                                    &layersId,
                                    &success);
          MOZ_ASSERT(success);
          unused << SendPRenderFrameConstructor(renderFrame);
        }
    }

    ShowInfo info(EmptyString(), false, false);
    if (mFrameElement) {
      nsAutoString name;
      mFrameElement->GetAttr(kNameSpaceID_None, nsGkAtoms::name, name);
      bool allowFullscreen =
        mFrameElement->HasAttr(kNameSpaceID_None, nsGkAtoms::allowfullscreen) ||
        mFrameElement->HasAttr(kNameSpaceID_None, nsGkAtoms::mozallowfullscreen);
      bool isPrivate = mFrameElement->HasAttr(kNameSpaceID_None, nsGkAtoms::mozprivatebrowsing);
      info = ShowInfo(name, allowFullscreen, isPrivate);
    }

    unused << SendShow(size, info, scrolling, textureFactoryIdentifier, layersId, renderFrame);
}

void
TabParent::UpdateDimensions(const nsIntRect& rect, const nsIntSize& size,
                            const nsIntPoint& aChromeDisp)
{
  if (mIsDestroyed) {
    return;
  }
  hal::ScreenConfiguration config;
  hal::GetCurrentScreenConfiguration(&config);
  ScreenOrientation orientation = config.orientation();

  if (!mUpdatedDimensions || mOrientation != orientation ||
      mDimensions != size || !mRect.IsEqualEdges(rect)) {
    mUpdatedDimensions = true;
    mRect = rect;
    mDimensions = size;
    mOrientation = orientation;

    unused << SendUpdateDimensions(mRect, mDimensions, mOrientation, aChromeDisp);
  }
}

void
TabParent::UpdateFrame(const FrameMetrics& aFrameMetrics)
{
  if (!mIsDestroyed) {
    unused << SendUpdateFrame(aFrameMetrics);
  }
}

void
TabParent::UIResolutionChanged()
{
  if (!mIsDestroyed) {
    // TryCacheDPIAndScale()'s cache is keyed off of
    // mDPI being greater than 0, so this invalidates it.
    mDPI = -1;
    unused << SendUIResolutionChanged();
  }
}

void
TabParent::AcknowledgeScrollUpdate(const ViewID& aScrollId, const uint32_t& aScrollGeneration)
{
  if (!mIsDestroyed) {
    unused << SendAcknowledgeScrollUpdate(aScrollId, aScrollGeneration);
  }
}

void TabParent::HandleDoubleTap(const CSSPoint& aPoint,
                                int32_t aModifiers,
                                const ScrollableLayerGuid &aGuid)
{
  if (!mIsDestroyed) {
    unused << SendHandleDoubleTap(aPoint, aGuid);
  }
}

void TabParent::HandleSingleTap(const CSSPoint& aPoint,
                                int32_t aModifiers,
                                const ScrollableLayerGuid &aGuid)
{
  // TODO Send the modifier data to TabChild for use in mouse events.
  if (!mIsDestroyed) {
    unused << SendHandleSingleTap(aPoint, aGuid);
  }
}

void TabParent::HandleLongTap(const CSSPoint& aPoint,
                              int32_t aModifiers,
                              const ScrollableLayerGuid &aGuid,
                              uint64_t aInputBlockId)
{
  if (!mIsDestroyed) {
    unused << SendHandleLongTap(aPoint, aGuid, aInputBlockId);
  }
}

void TabParent::HandleLongTapUp(const CSSPoint& aPoint,
                                int32_t aModifiers,
                                const ScrollableLayerGuid &aGuid)
{
  if (!mIsDestroyed) {
    unused << SendHandleLongTapUp(aPoint, aGuid);
  }
}

void TabParent::NotifyAPZStateChange(ViewID aViewId,
                                     APZStateChange aChange,
                                     int aArg)
{
  if (!mIsDestroyed) {
    unused << SendNotifyAPZStateChange(aViewId, aChange, aArg);
  }
}

void
TabParent::Activate()
{
  if (!mIsDestroyed) {
    unused << SendActivate();
  }
}

void
TabParent::Deactivate()
{
  if (!mIsDestroyed) {
    unused << SendDeactivate();
  }
}

NS_IMETHODIMP
TabParent::Init(nsIDOMWindow *window)
{
  return NS_OK;
}

NS_IMETHODIMP
TabParent::GetState(uint32_t *aState)
{
  NS_ENSURE_ARG(aState);
  NS_WARNING("SecurityState not valid here");
  *aState = 0;
  return NS_OK;
}

NS_IMETHODIMP
TabParent::SetDocShell(nsIDocShell *aDocShell)
{
  NS_ENSURE_ARG(aDocShell);
  NS_WARNING("No mDocShell member in TabParent so there is no docShell to set");
  return NS_OK;
}

PDocumentRendererParent*
TabParent::AllocPDocumentRendererParent(const nsRect& documentRect,
                                        const gfx::Matrix& transform,
                                        const nsString& bgcolor,
                                        const uint32_t& renderFlags,
                                        const bool& flushLayout,
                                        const nsIntSize& renderSize)
{
    return new DocumentRendererParent();
}

bool
TabParent::DeallocPDocumentRendererParent(PDocumentRendererParent* actor)
{
    delete actor;
    return true;
}

PContentPermissionRequestParent*
TabParent::AllocPContentPermissionRequestParent(const InfallibleTArray<PermissionRequest>& aRequests,
                                                const IPC::Principal& aPrincipal)
{
  return nsContentPermissionUtils::CreateContentPermissionRequestParent(aRequests, mFrameElement, aPrincipal);
}

bool
TabParent::DeallocPContentPermissionRequestParent(PContentPermissionRequestParent* actor)
{
  delete actor;
  return true;
}

PFilePickerParent*
TabParent::AllocPFilePickerParent(const nsString& aTitle, const int16_t& aMode)
{
  return new FilePickerParent(aTitle, aMode);
}

bool
TabParent::DeallocPFilePickerParent(PFilePickerParent* actor)
{
  delete actor;
  return true;
}

auto
TabParent::AllocPIndexedDBPermissionRequestParent(const Principal& aPrincipal)
  -> PIndexedDBPermissionRequestParent*
{
  MOZ_ASSERT(NS_IsMainThread());

  nsCOMPtr<nsIPrincipal> principal(aPrincipal);
  if (!principal) {
    return nullptr;
  }

  nsCOMPtr<nsIContentParent> manager = Manager();
  if (manager->IsContentParent()) {
    if (NS_WARN_IF(!AssertAppPrincipal(manager->AsContentParent(),
                                       principal))) {
      return nullptr;
    }
  } else {
    MOZ_CRASH("Figure out security checks for bridged content!");
  }

  nsCOMPtr<nsPIDOMWindow> window;
  nsCOMPtr<nsIContent> frame = do_QueryInterface(mFrameElement);
  if (frame) {
    MOZ_ASSERT(frame->OwnerDoc());
    window = do_QueryInterface(frame->OwnerDoc()->GetWindow());
  }

  if (!window) {
    return nullptr;
  }

  return
    mozilla::dom::indexedDB::AllocPIndexedDBPermissionRequestParent(window,
                                                                    principal);
}

bool
TabParent::RecvPIndexedDBPermissionRequestConstructor(
                                      PIndexedDBPermissionRequestParent* aActor,
                                      const Principal& aPrincipal)
{
  MOZ_ASSERT(NS_IsMainThread());
  MOZ_ASSERT(aActor);

  return
    mozilla::dom::indexedDB::RecvPIndexedDBPermissionRequestConstructor(aActor);
}

bool
TabParent::DeallocPIndexedDBPermissionRequestParent(
                                      PIndexedDBPermissionRequestParent* aActor)
{
  MOZ_ASSERT(NS_IsMainThread());
  MOZ_ASSERT(aActor);

  return
    mozilla::dom::indexedDB::DeallocPIndexedDBPermissionRequestParent(aActor);
}

void
TabParent::SendMouseEvent(const nsAString& aType, float aX, float aY,
                          int32_t aButton, int32_t aClickCount,
                          int32_t aModifiers, bool aIgnoreRootScrollFrame)
{
  if (!mIsDestroyed) {
    unused << PBrowserParent::SendMouseEvent(nsString(aType), aX, aY,
                                             aButton, aClickCount,
                                             aModifiers, aIgnoreRootScrollFrame);
  }
}

void
TabParent::SendKeyEvent(const nsAString& aType,
                        int32_t aKeyCode,
                        int32_t aCharCode,
                        int32_t aModifiers,
                        bool aPreventDefault)
{
  if (!mIsDestroyed) {
    unused << PBrowserParent::SendKeyEvent(nsString(aType), aKeyCode, aCharCode,
                                           aModifiers, aPreventDefault);
  }
}

bool
TabParent::MapEventCoordinatesForChildProcess(WidgetEvent* aEvent)
{
  nsRefPtr<nsFrameLoader> frameLoader = GetFrameLoader();
  if (!frameLoader) {
    return false;
  }
  LayoutDeviceIntPoint offset =
    EventStateManager::GetChildProcessOffset(frameLoader, *aEvent);
  MapEventCoordinatesForChildProcess(offset, aEvent);
  return true;
}

void
TabParent::MapEventCoordinatesForChildProcess(
  const LayoutDeviceIntPoint& aOffset, WidgetEvent* aEvent)
{
  if (aEvent->mClass != eTouchEventClass) {
    aEvent->refPoint = aOffset;
  } else {
    aEvent->refPoint = LayoutDeviceIntPoint();
    // Then offset all the touch points by that distance, to put them
    // in the space where top-left is 0,0.
    const WidgetTouchEvent::TouchArray& touches =
      aEvent->AsTouchEvent()->touches;
    for (uint32_t i = 0; i < touches.Length(); ++i) {
      Touch* touch = touches[i];
      if (touch) {
        touch->mRefPoint += LayoutDeviceIntPoint::ToUntyped(aOffset);
      }
    }
  }
}

bool TabParent::SendRealMouseEvent(WidgetMouseEvent& event)
{
  if (mIsDestroyed) {
    return false;
  }
  nsEventStatus status = MaybeForwardEventToRenderFrame(event, nullptr, nullptr);
  if (status == nsEventStatus_eConsumeNoDefault ||
      !MapEventCoordinatesForChildProcess(&event)) {
    return false;
  }
  return PBrowserParent::SendRealMouseEvent(event);
}

CSSPoint TabParent::AdjustTapToChildWidget(const CSSPoint& aPoint)
{
  nsCOMPtr<nsIContent> content = do_QueryInterface(mFrameElement);

  if (!content || !content->OwnerDoc()) {
    return aPoint;
  }

  nsIDocument* doc = content->OwnerDoc();
  if (!doc || !doc->GetShell()) {
    return aPoint;
  }
  nsPresContext* presContext = doc->GetShell()->GetPresContext();

  return aPoint + CSSPoint(
    presContext->DevPixelsToFloatCSSPixels(mChildProcessOffsetAtTouchStart.x),
    presContext->DevPixelsToFloatCSSPixels(mChildProcessOffsetAtTouchStart.y));
}

bool TabParent::SendHandleSingleTap(const CSSPoint& aPoint, const ScrollableLayerGuid& aGuid)
{
  if (mIsDestroyed) {
    return false;
  }

  return PBrowserParent::SendHandleSingleTap(AdjustTapToChildWidget(aPoint), aGuid);
}

bool TabParent::SendHandleLongTap(const CSSPoint& aPoint, const ScrollableLayerGuid& aGuid, const uint64_t& aInputBlockId)
{
  if (mIsDestroyed) {
    return false;
  }

  return PBrowserParent::SendHandleLongTap(AdjustTapToChildWidget(aPoint), aGuid, aInputBlockId);
}

bool TabParent::SendHandleLongTapUp(const CSSPoint& aPoint, const ScrollableLayerGuid& aGuid)
{
  if (mIsDestroyed) {
    return false;
  }

  return PBrowserParent::SendHandleLongTapUp(AdjustTapToChildWidget(aPoint), aGuid);
}

bool TabParent::SendHandleDoubleTap(const CSSPoint& aPoint, const ScrollableLayerGuid& aGuid)
{
  if (mIsDestroyed) {
    return false;
  }

  return PBrowserParent::SendHandleDoubleTap(AdjustTapToChildWidget(aPoint), aGuid);
}

bool TabParent::SendMouseWheelEvent(WidgetWheelEvent& event)
{
  if (mIsDestroyed) {
    return false;
  }

  ScrollableLayerGuid guid;
  uint64_t blockId;
  nsEventStatus status = MaybeForwardEventToRenderFrame(event, &guid, &blockId);
  if (status == nsEventStatus_eConsumeNoDefault ||
      !MapEventCoordinatesForChildProcess(&event))
  {
    return false;
  }
  return PBrowserParent::SendMouseWheelEvent(event, guid, blockId);
}

static void
DoCommandCallback(mozilla::Command aCommand, void* aData)
{
  static_cast<InfallibleTArray<mozilla::CommandInt>*>(aData)->AppendElement(aCommand);
}

bool
TabParent::RecvRequestNativeKeyBindings(const WidgetKeyboardEvent& aEvent,
                                        MaybeNativeKeyBinding* aBindings)
{
  AutoInfallibleTArray<mozilla::CommandInt, 4> singleLine;
  AutoInfallibleTArray<mozilla::CommandInt, 4> multiLine;
  AutoInfallibleTArray<mozilla::CommandInt, 4> richText;

  *aBindings = mozilla::void_t();

  nsCOMPtr<nsIWidget> widget = GetWidget();
  if (!widget) {
    return true;
  }

  WidgetKeyboardEvent localEvent(aEvent);

  if (NS_FAILED(widget->AttachNativeKeyEvent(localEvent))) {
    return true;
  }

  widget->ExecuteNativeKeyBinding(nsIWidget::NativeKeyBindingsForSingleLineEditor,
                                  localEvent, DoCommandCallback, &singleLine);
  widget->ExecuteNativeKeyBinding(nsIWidget::NativeKeyBindingsForMultiLineEditor,
                                  localEvent, DoCommandCallback, &multiLine);
  widget->ExecuteNativeKeyBinding(nsIWidget::NativeKeyBindingsForRichTextEditor,
                                  localEvent, DoCommandCallback, &richText);

  if (!singleLine.IsEmpty() || !multiLine.IsEmpty() || !richText.IsEmpty()) {
    *aBindings = NativeKeyBinding(singleLine, multiLine, richText);
  }

  return true;
}

bool TabParent::SendRealKeyEvent(WidgetKeyboardEvent& event)
{
  if (mIsDestroyed) {
    return false;
  }
  MaybeForwardEventToRenderFrame(event, nullptr, nullptr);
  if (!MapEventCoordinatesForChildProcess(&event)) {
    return false;
  }


  MaybeNativeKeyBinding bindings;
  bindings = void_t();
  if (event.message == NS_KEY_PRESS) {
    nsCOMPtr<nsIWidget> widget = GetWidget();

    AutoInfallibleTArray<mozilla::CommandInt, 4> singleLine;
    AutoInfallibleTArray<mozilla::CommandInt, 4> multiLine;
    AutoInfallibleTArray<mozilla::CommandInt, 4> richText;

    widget->ExecuteNativeKeyBinding(nsIWidget::NativeKeyBindingsForSingleLineEditor,
                                    event, DoCommandCallback, &singleLine);
    widget->ExecuteNativeKeyBinding(nsIWidget::NativeKeyBindingsForMultiLineEditor,
                                    event, DoCommandCallback, &multiLine);
    widget->ExecuteNativeKeyBinding(nsIWidget::NativeKeyBindingsForRichTextEditor,
                                    event, DoCommandCallback, &richText);

    if (!singleLine.IsEmpty() || !multiLine.IsEmpty() || !richText.IsEmpty()) {
      bindings = NativeKeyBinding(singleLine, multiLine, richText);
    }
  }

  return PBrowserParent::SendRealKeyEvent(event, bindings);
}

bool TabParent::SendRealTouchEvent(WidgetTouchEvent& event)
{
  if (mIsDestroyed) {
    return false;
  }
  if (event.message == NS_TOUCH_START) {
    // Adjust the widget coordinates to be relative to our frame.
    nsRefPtr<nsFrameLoader> frameLoader = GetFrameLoader();
    if (!frameLoader) {
      // No frame anymore?
      sEventCapturer = nullptr;
      return false;
    }

    mChildProcessOffsetAtTouchStart =
      EventStateManager::GetChildProcessOffset(frameLoader, event);

    MOZ_ASSERT((!sEventCapturer && mEventCaptureDepth == 0) ||
               (sEventCapturer == this && mEventCaptureDepth > 0));
    // We want to capture all remaining touch events in this series
    // for fast-path dispatch.
    sEventCapturer = this;
    ++mEventCaptureDepth;
  }

  // PresShell::HandleEventInternal adds touches on touch end/cancel.  This
  // confuses remote content and the panning and zooming logic into thinking
  // that the added touches are part of the touchend/cancel, when actually
  // they're not.
  if (event.message == NS_TOUCH_END || event.message == NS_TOUCH_CANCEL) {
    for (int i = event.touches.Length() - 1; i >= 0; i--) {
      if (!event.touches[i]->mChanged) {
        event.touches.RemoveElementAt(i);
      }
    }
  }

  ScrollableLayerGuid guid;
  uint64_t blockId;
  nsEventStatus status = MaybeForwardEventToRenderFrame(event, &guid, &blockId);

  if (status == nsEventStatus_eConsumeNoDefault || mIsDestroyed) {
    return false;
  }

  MapEventCoordinatesForChildProcess(mChildProcessOffsetAtTouchStart, &event);

  return (event.message == NS_TOUCH_MOVE) ?
    PBrowserParent::SendRealTouchMoveEvent(event, guid, blockId) :
    PBrowserParent::SendRealTouchEvent(event, guid, blockId);
}

/*static*/ TabParent*
TabParent::GetEventCapturer()
{
  return sEventCapturer;
}

bool
TabParent::TryCapture(const WidgetGUIEvent& aEvent)
{
  MOZ_ASSERT(sEventCapturer == this && mEventCaptureDepth > 0);

  if (aEvent.mClass != eTouchEventClass) {
    // Only capture of touch events is implemented, for now.
    return false;
  }

  WidgetTouchEvent event(*aEvent.AsTouchEvent());

  bool isTouchPointUp = (event.message == NS_TOUCH_END ||
                         event.message == NS_TOUCH_CANCEL);
  if (event.message == NS_TOUCH_START || isTouchPointUp) {
    // Let the DOM see touch start/end events so that its touch-point
    // state stays consistent.
    if (isTouchPointUp && 0 == --mEventCaptureDepth) {
      // All event series are un-captured, don't try to catch any
      // more.
      sEventCapturer = nullptr;
    }
    return false;
  }

  SendRealTouchEvent(event);
  return true;
}

bool
TabParent::RecvSyncMessage(const nsString& aMessage,
                           const ClonedMessageData& aData,
                           const InfallibleTArray<CpowEntry>& aCpows,
                           const IPC::Principal& aPrincipal,
                           InfallibleTArray<nsString>* aJSONRetVal)
{
  // FIXME Permission check for TabParent in Content process
  nsIPrincipal* principal = aPrincipal;
  if (Manager()->IsContentParent()) {
    ContentParent* parent = Manager()->AsContentParent();
    if (!ContentParent::IgnoreIPCPrincipal() &&
        parent && principal && !AssertAppPrincipal(parent, principal)) {
      return false;
    }
  }

  StructuredCloneData cloneData = ipc::UnpackClonedMessageDataForParent(aData);
  CpowIdHolder cpows(Manager(), aCpows);
  return ReceiveMessage(aMessage, true, &cloneData, &cpows, aPrincipal, aJSONRetVal);
}

bool
TabParent::RecvRpcMessage(const nsString& aMessage,
                          const ClonedMessageData& aData,
                          const InfallibleTArray<CpowEntry>& aCpows,
                          const IPC::Principal& aPrincipal,
                          InfallibleTArray<nsString>* aJSONRetVal)
{
  // FIXME Permission check for TabParent in Content process
  nsIPrincipal* principal = aPrincipal;
  if (Manager()->IsContentParent()) {
    ContentParent* parent = Manager()->AsContentParent();
    if (!ContentParent::IgnoreIPCPrincipal() &&
        parent && principal && !AssertAppPrincipal(parent, principal)) {
      return false;
    }
  }

  StructuredCloneData cloneData = ipc::UnpackClonedMessageDataForParent(aData);
  CpowIdHolder cpows(Manager(), aCpows);
  return ReceiveMessage(aMessage, true, &cloneData, &cpows, aPrincipal, aJSONRetVal);
}

bool
TabParent::RecvAsyncMessage(const nsString& aMessage,
                            const ClonedMessageData& aData,
                            const InfallibleTArray<CpowEntry>& aCpows,
                            const IPC::Principal& aPrincipal)
{
  // FIXME Permission check for TabParent in Content process
  nsIPrincipal* principal = aPrincipal;
  if (Manager()->IsContentParent()) {
    ContentParent* parent = Manager()->AsContentParent();
    if (!ContentParent::IgnoreIPCPrincipal() &&
        parent && principal && !AssertAppPrincipal(parent, principal)) {
      return false;
    }
  }

  StructuredCloneData cloneData = ipc::UnpackClonedMessageDataForParent(aData);
  CpowIdHolder cpows(Manager(), aCpows);
  return ReceiveMessage(aMessage, false, &cloneData, &cpows, aPrincipal, nullptr);
}

bool
TabParent::RecvSetCursor(const uint32_t& aCursor, const bool& aForce)
{
  nsCOMPtr<nsIWidget> widget = GetWidget();
  if (widget) {
    if (aForce) {
      widget->ClearCachedCursor();
    }
    widget->SetCursor((nsCursor) aCursor);
  }
  return true;
}

bool
TabParent::RecvSetBackgroundColor(const nscolor& aColor)
{
  if (RenderFrameParent* frame = GetRenderFrame()) {
    frame->SetBackgroundColor(aColor);
  }
  return true;
}

nsIXULBrowserWindow*
TabParent::GetXULBrowserWindow()
{
  nsCOMPtr<nsIContent> frame = do_QueryInterface(mFrameElement);
  if (!frame) {
    return nullptr;
  }

  nsCOMPtr<nsIDocShell> docShell = frame->OwnerDoc()->GetDocShell();
  if (!docShell) {
    return nullptr;
  }

  nsCOMPtr<nsIDocShellTreeOwner> treeOwner;
  docShell->GetTreeOwner(getter_AddRefs(treeOwner));
  if (!treeOwner) {
    return nullptr;
  }

  nsCOMPtr<nsIXULWindow> window = do_GetInterface(treeOwner);
  if (!window) {
    return nullptr;
  }

  nsCOMPtr<nsIXULBrowserWindow> xulBrowserWindow;
  window->GetXULBrowserWindow(getter_AddRefs(xulBrowserWindow));
  return xulBrowserWindow;
}

bool
TabParent::RecvSetStatus(const uint32_t& aType, const nsString& aStatus)
{
  nsCOMPtr<nsIXULBrowserWindow> xulBrowserWindow = GetXULBrowserWindow();
  if (!xulBrowserWindow) {
    return true;
  }

  switch (aType) {
   case nsIWebBrowserChrome::STATUS_SCRIPT:
    xulBrowserWindow->SetJSStatus(aStatus);
    break;
   case nsIWebBrowserChrome::STATUS_LINK:
    xulBrowserWindow->SetOverLink(aStatus, nullptr);
    break;
  }
  return true;
}

bool
TabParent::RecvShowTooltip(const uint32_t& aX, const uint32_t& aY, const nsString& aTooltip)
{
  nsCOMPtr<nsIXULBrowserWindow> xulBrowserWindow = GetXULBrowserWindow();
  if (!xulBrowserWindow) {
    return true;
  }

  xulBrowserWindow->ShowTooltip(aX, aY, aTooltip);
  return true;
}

bool
TabParent::RecvHideTooltip()
{
  nsCOMPtr<nsIXULBrowserWindow> xulBrowserWindow = GetXULBrowserWindow();
  if (!xulBrowserWindow) {
    return true;
  }

  xulBrowserWindow->HideTooltip();
  return true;
}

bool
TabParent::RecvNotifyIMEFocus(const bool& aFocus,
                              nsIMEUpdatePreference* aPreference,
                              uint32_t* aSeqno)
{
  nsCOMPtr<nsIWidget> widget = GetWidget();
  if (!widget) {
    *aPreference = nsIMEUpdatePreference();
    return true;
  }

  *aSeqno = mIMESeqno;
  mIMETabParent = aFocus ? this : nullptr;
  mIMESelectionAnchor = 0;
  mIMESelectionFocus = 0;
  widget->NotifyIME(IMENotification(aFocus ? NOTIFY_IME_OF_FOCUS :
                                             NOTIFY_IME_OF_BLUR));

  if (aFocus) {
    *aPreference = widget->GetIMEUpdatePreference();
  } else {
    mIMECacheText.Truncate(0);
  }
  return true;
}

bool
TabParent::RecvNotifyIMETextChange(const uint32_t& aStart,
                                   const uint32_t& aEnd,
                                   const uint32_t& aNewEnd,
                                   const bool& aCausedByComposition)
{
  nsCOMPtr<nsIWidget> widget = GetWidget();
  if (!widget)
    return true;

#ifdef DEBUG
  nsIMEUpdatePreference updatePreference = widget->GetIMEUpdatePreference();
  NS_ASSERTION(updatePreference.WantTextChange(),
               "Don't call Send/RecvNotifyIMETextChange without NOTIFY_TEXT_CHANGE");
  MOZ_ASSERT(!aCausedByComposition ||
               updatePreference.WantChangesCausedByComposition(),
    "The widget doesn't want text change notification caused by composition");
#endif

  IMENotification notification(NOTIFY_IME_OF_TEXT_CHANGE);
  notification.mTextChangeData.mStartOffset = aStart;
  notification.mTextChangeData.mOldEndOffset = aEnd;
  notification.mTextChangeData.mNewEndOffset = aNewEnd;
  notification.mTextChangeData.mCausedByComposition = aCausedByComposition;
  widget->NotifyIME(notification);
  return true;
}

bool
TabParent::RecvNotifyIMESelectedCompositionRect(
  const uint32_t& aOffset,
  const InfallibleTArray<nsIntRect>& aRects,
  const uint32_t& aCaretOffset,
  const nsIntRect& aCaretRect)
{
  // add rect to cache for another query
  mIMECompositionRectOffset = aOffset;
  mIMECompositionRects = aRects;
  mIMECaretOffset = aCaretOffset;
  mIMECaretRect = aCaretRect;

  nsCOMPtr<nsIWidget> widget = GetWidget();
  if (!widget) {
    return true;
  }
  widget->NotifyIME(IMENotification(NOTIFY_IME_OF_COMPOSITION_UPDATE));
  return true;
}

bool
TabParent::RecvNotifyIMESelection(const uint32_t& aSeqno,
                                  const uint32_t& aAnchor,
                                  const uint32_t& aFocus,
                                  const mozilla::WritingMode& aWritingMode,
                                  const bool& aCausedByComposition)
{
  nsCOMPtr<nsIWidget> widget = GetWidget();
  if (!widget)
    return true;

  if (aSeqno == mIMESeqno) {
    mIMESelectionAnchor = aAnchor;
    mIMESelectionFocus = aFocus;
    mWritingMode = aWritingMode;
    const nsIMEUpdatePreference updatePreference =
      widget->GetIMEUpdatePreference();
    if (updatePreference.WantSelectionChange() &&
        (updatePreference.WantChangesCausedByComposition() ||
         !aCausedByComposition)) {
      IMENotification notification(NOTIFY_IME_OF_SELECTION_CHANGE);
      notification.mSelectionChangeData.mCausedByComposition =
        aCausedByComposition;
      widget->NotifyIME(notification);
    }
  }
  return true;
}

bool
TabParent::RecvNotifyIMETextHint(const nsString& aText)
{
  // Replace our cache with new text
  mIMECacheText = aText;
  return true;
}

bool
TabParent::RecvNotifyIMEMouseButtonEvent(
             const IMENotification& aIMENotification,
             bool* aConsumedByIME)
{

  nsCOMPtr<nsIWidget> widget = GetWidget();
  if (!widget) {
    *aConsumedByIME = false;
    return true;
  }
  nsresult rv = widget->NotifyIME(aIMENotification);
  *aConsumedByIME = rv == NS_SUCCESS_EVENT_CONSUMED;
  return true;
}

bool
TabParent::RecvRequestFocus(const bool& aCanRaise)
{
  nsCOMPtr<nsIFocusManager> fm = nsFocusManager::GetFocusManager();
  if (!fm) {
    return true;
  }

  nsCOMPtr<nsIContent> content = do_QueryInterface(mFrameElement);
  if (!content || !content->OwnerDoc()) {
    return true;
  }

  uint32_t flags = nsIFocusManager::FLAG_NOSCROLL;
  if (aCanRaise)
    flags |= nsIFocusManager::FLAG_RAISE;

  nsCOMPtr<nsIDOMElement> node = do_QueryInterface(mFrameElement);
  fm->SetFocus(node, flags);
  return true;
}

bool
TabParent::RecvEnableDisableCommands(const nsString& aAction,
                                     const nsTArray<nsCString>& aEnabledCommands,
                                     const nsTArray<nsCString>& aDisabledCommands)
{
  nsCOMPtr<nsIRemoteBrowser> remoteBrowser = do_QueryInterface(mFrameElement);
  if (remoteBrowser) {
    nsAutoArrayPtr<const char*> enabledCommands, disabledCommands;

    if (aEnabledCommands.Length()) {
      enabledCommands = new const char* [aEnabledCommands.Length()];
      for (uint32_t c = 0; c < aEnabledCommands.Length(); c++) {
        enabledCommands[c] = aEnabledCommands[c].get();
      }
    }

    if (aDisabledCommands.Length()) {
      disabledCommands = new const char* [aDisabledCommands.Length()];
      for (uint32_t c = 0; c < aDisabledCommands.Length(); c++) {
        disabledCommands[c] = aDisabledCommands[c].get();
      }
    }

    remoteBrowser->EnableDisableCommands(aAction,
                                         aEnabledCommands.Length(), enabledCommands,
                                         aDisabledCommands.Length(), disabledCommands);
  }

  return true;
}

nsIntPoint
TabParent::GetChildProcessOffset()
{
  // The "toplevel widget" in child processes is always at position
  // 0,0.  Map the event coordinates to match that.

  nsIntPoint offset(0, 0);
  nsRefPtr<nsFrameLoader> frameLoader = GetFrameLoader();
  if (!frameLoader) {
    return offset;
  }
  nsIFrame* targetFrame = frameLoader->GetPrimaryFrameOfOwningContent();
  if (!targetFrame) {
    return offset;
  }

  // Find out how far we're offset from the nearest widget.
  nsCOMPtr<nsIWidget> widget = GetWidget();
  if (!widget) {
    return offset;
  }
  nsPoint pt = nsLayoutUtils::GetEventCoordinatesRelativeTo(widget,
                                                            nsIntPoint(0, 0),
                                                            targetFrame);

  return LayoutDeviceIntPoint::ToUntyped(LayoutDeviceIntPoint::FromAppUnitsToNearest(
           pt, targetFrame->PresContext()->AppUnitsPerDevPixel()));
}

bool
TabParent::RecvReplyKeyEvent(const WidgetKeyboardEvent& event)
{
  NS_ENSURE_TRUE(mFrameElement, true);

  WidgetKeyboardEvent localEvent(event);
  // Set mNoCrossProcessBoundaryForwarding to avoid this event from
  // being infinitely redispatched and forwarded to the child again.
  localEvent.mFlags.mNoCrossProcessBoundaryForwarding = true;

  // Here we convert the WidgetEvent that we received to an nsIDOMEvent
  // to be able to dispatch it to the <browser> element as the target element.
  nsIDocument* doc = mFrameElement->OwnerDoc();
  nsIPresShell* presShell = doc->GetShell();
  NS_ENSURE_TRUE(presShell, true);
  nsPresContext* presContext = presShell->GetPresContext();
  NS_ENSURE_TRUE(presContext, true);

  EventDispatcher::Dispatch(mFrameElement, presContext, &localEvent);
  return true;
}

bool
TabParent::RecvDispatchAfterKeyboardEvent(const WidgetKeyboardEvent& aEvent)
{
  NS_ENSURE_TRUE(mFrameElement, true);

  WidgetKeyboardEvent localEvent(aEvent);
  localEvent.widget = GetWidget();

  nsIDocument* doc = mFrameElement->OwnerDoc();
  nsCOMPtr<nsIPresShell> presShell = doc->GetShell();
  NS_ENSURE_TRUE(presShell, true);

  if (mFrameElement &&
      PresShell::BeforeAfterKeyboardEventEnabled() &&
      localEvent.message != NS_KEY_PRESS) {
    nsCOMPtr<nsINode> node(do_QueryInterface(mFrameElement));
    presShell->DispatchAfterKeyboardEvent(mFrameElement, localEvent,
                                          aEvent.mFlags.mDefaultPrevented);
  }

  return true;
}

/**
 * Try to answer query event using cached text.
 *
 * For NS_QUERY_SELECTED_TEXT, fail if the cache doesn't contain the whole
 *  selected range. (This shouldn't happen because PuppetWidget should have
 *  already sent the whole selection.)
 *
 * For NS_QUERY_TEXT_CONTENT, fail only if the cache doesn't overlap with
 *  the queried range. Note the difference from above. We use
 *  this behavior because a normal NS_QUERY_TEXT_CONTENT event is allowed to
 *  have out-of-bounds offsets, so that widget can request content without
 *  knowing the exact length of text. It's up to widget to handle cases when
 *  the returned offset/length are different from the queried offset/length.
 *
 * For NS_QUERY_TEXT_RECT, fail if cached offset/length aren't equals to input.
 *   Cocoa widget always queries selected offset, so it works on it.
 *
 * For NS_QUERY_CARET_RECT, fail if cached offset isn't equals to input
 */
bool
TabParent::HandleQueryContentEvent(WidgetQueryContentEvent& aEvent)
{
  aEvent.mSucceeded = false;
  aEvent.mWasAsync = false;
  aEvent.mReply.mFocusedWidget = nsCOMPtr<nsIWidget>(GetWidget()).get();

  switch (aEvent.message)
  {
  case NS_QUERY_SELECTED_TEXT:
    {
      aEvent.mReply.mOffset = std::min(mIMESelectionAnchor, mIMESelectionFocus);
      if (mIMESelectionAnchor == mIMESelectionFocus) {
        aEvent.mReply.mString.Truncate(0);
      } else {
        if (mIMESelectionAnchor > mIMECacheText.Length() ||
            mIMESelectionFocus > mIMECacheText.Length()) {
          break;
        }
        uint32_t selLen = mIMESelectionAnchor > mIMESelectionFocus ?
                          mIMESelectionAnchor - mIMESelectionFocus :
                          mIMESelectionFocus - mIMESelectionAnchor;
        aEvent.mReply.mString = Substring(mIMECacheText,
                                          aEvent.mReply.mOffset,
                                          selLen);
      }
      aEvent.mReply.mReversed = mIMESelectionFocus < mIMESelectionAnchor;
      aEvent.mReply.mHasSelection = true;
      aEvent.mReply.mWritingMode = mWritingMode;
      aEvent.mSucceeded = true;
    }
    break;
  case NS_QUERY_TEXT_CONTENT:
    {
      uint32_t inputOffset = aEvent.mInput.mOffset,
               inputEnd = inputOffset + aEvent.mInput.mLength;

      if (inputEnd > mIMECacheText.Length()) {
        inputEnd = mIMECacheText.Length();
      }
      if (inputEnd < inputOffset) {
        break;
      }
      aEvent.mReply.mOffset = inputOffset;
      aEvent.mReply.mString = Substring(mIMECacheText,
                                        inputOffset,
                                        inputEnd - inputOffset);
      aEvent.mSucceeded = true;
    }
    break;
  case NS_QUERY_TEXT_RECT:
    {
      if (aEvent.mInput.mOffset < mIMECompositionRectOffset ||
          (aEvent.mInput.mOffset + aEvent.mInput.mLength >
            mIMECompositionRectOffset + mIMECompositionRects.Length())) {
        // XXX
        // we doesn't have cache for this request.
        break;
      }

      uint32_t baseOffset = aEvent.mInput.mOffset - mIMECompositionRectOffset;
      uint32_t endOffset = baseOffset + aEvent.mInput.mLength;
      aEvent.mReply.mRect.SetEmpty();
      for (uint32_t i = baseOffset; i < endOffset; i++) {
        aEvent.mReply.mRect =
          aEvent.mReply.mRect.Union(mIMECompositionRects[i]);
      }
      aEvent.mReply.mOffset = aEvent.mInput.mOffset;
      aEvent.mReply.mRect = aEvent.mReply.mRect - GetChildProcessOffset();
      aEvent.mSucceeded = true;
    }
    break;
  case NS_QUERY_CARET_RECT:
    {
      if (aEvent.mInput.mOffset != mIMECaretOffset) {
        break;
      }

      aEvent.mReply.mOffset = mIMECaretOffset;
      aEvent.mReply.mRect = mIMECaretRect - GetChildProcessOffset();
      aEvent.mSucceeded = true;
    }
    break;
  }
  return true;
}

bool
TabParent::SendCompositionEvent(WidgetCompositionEvent& event)
{
  if (mIsDestroyed) {
    return false;
  }

  if (event.CausesDOMTextEvent()) {
    return SendCompositionChangeEvent(event);
  }

  mIMEComposing = !event.CausesDOMCompositionEndEvent();
  mIMECompositionStart = std::min(mIMESelectionAnchor, mIMESelectionFocus);
  if (mIMECompositionEnding)
    return true;
  event.mSeqno = ++mIMESeqno;
  return PBrowserParent::SendCompositionEvent(event);
}

/**
 * During REQUEST_TO_COMMIT_COMPOSITION or REQUEST_TO_CANCEL_COMPOSITION,
 * widget usually sends a NS_COMPOSITION_CHANGE event to finalize or
 * clear the composition, respectively
 *
 * Because the event will not reach content in time, we intercept it
 * here and pass the text as the EndIMEComposition return value
 */
bool
TabParent::SendCompositionChangeEvent(WidgetCompositionEvent& event)
{
  if (mIMECompositionEnding) {
    mIMECompositionText = event.mData;
    return true;
  }

  // We must be able to simulate the selection because
  // we might not receive selection updates in time
  if (!mIMEComposing) {
    mIMECompositionStart = std::min(mIMESelectionAnchor, mIMESelectionFocus);
  }
  mIMESelectionAnchor = mIMESelectionFocus =
      mIMECompositionStart + event.mData.Length();
  mIMEComposing = !event.CausesDOMCompositionEndEvent();

  event.mSeqno = ++mIMESeqno;
  return PBrowserParent::SendCompositionEvent(event);
}

bool
TabParent::SendSelectionEvent(WidgetSelectionEvent& event)
{
  if (mIsDestroyed) {
    return false;
  }
  mIMESelectionAnchor = event.mOffset + (event.mReversed ? event.mLength : 0);
  mIMESelectionFocus = event.mOffset + (!event.mReversed ? event.mLength : 0);
  event.mSeqno = ++mIMESeqno;
  return PBrowserParent::SendSelectionEvent(event);
}

/*static*/ TabParent*
TabParent::GetFrom(nsFrameLoader* aFrameLoader)
{
  if (!aFrameLoader) {
    return nullptr;
  }
  PBrowserParent* remoteBrowser = aFrameLoader->GetRemoteBrowser();
  return static_cast<TabParent*>(remoteBrowser);
}

/*static*/ TabParent*
TabParent::GetFrom(nsIContent* aContent)
{
  nsCOMPtr<nsIFrameLoaderOwner> loaderOwner = do_QueryInterface(aContent);
  if (!loaderOwner) {
    return nullptr;
  }
  nsRefPtr<nsFrameLoader> frameLoader = loaderOwner->GetFrameLoader();
  return GetFrom(frameLoader);
}

/*static*/ TabId
TabParent::GetTabIdFrom(nsIDocShell *docShell)
{
  nsCOMPtr<nsITabChild> tabChild(TabChild::GetFrom(docShell));
  if (tabChild) {
    return static_cast<TabChild*>(tabChild.get())->GetTabId();
  }
  return TabId(0);
}

RenderFrameParent*
TabParent::GetRenderFrame()
{
  if (ManagedPRenderFrameParent().IsEmpty()) {
    return nullptr;
  }
  return static_cast<RenderFrameParent*>(ManagedPRenderFrameParent()[0]);
}

bool
TabParent::RecvEndIMEComposition(const bool& aCancel,
                                 nsString* aComposition)
{
  nsCOMPtr<nsIWidget> widget = GetWidget();
  if (!widget)
    return true;

  mIMECompositionEnding = true;

  widget->NotifyIME(IMENotification(aCancel ? REQUEST_TO_CANCEL_COMPOSITION :
                                              REQUEST_TO_COMMIT_COMPOSITION));

  mIMECompositionEnding = false;
  *aComposition = mIMECompositionText;
  mIMECompositionText.Truncate(0);  
  return true;
}

bool
TabParent::RecvGetInputContext(int32_t* aIMEEnabled,
                               int32_t* aIMEOpen,
                               intptr_t* aNativeIMEContext)
{
  nsCOMPtr<nsIWidget> widget = GetWidget();
  if (!widget) {
    *aIMEEnabled = IMEState::DISABLED;
    *aIMEOpen = IMEState::OPEN_STATE_NOT_SUPPORTED;
    *aNativeIMEContext = 0;
    return true;
  }

  InputContext context = widget->GetInputContext();
  *aIMEEnabled = static_cast<int32_t>(context.mIMEState.mEnabled);
  *aIMEOpen = static_cast<int32_t>(context.mIMEState.mOpen);
  *aNativeIMEContext = reinterpret_cast<intptr_t>(context.mNativeIMEContext);
  return true;
}

bool
TabParent::RecvSetInputContext(const int32_t& aIMEEnabled,
                               const int32_t& aIMEOpen,
                               const nsString& aType,
                               const nsString& aInputmode,
                               const nsString& aActionHint,
                               const int32_t& aCause,
                               const int32_t& aFocusChange)
{
  // mIMETabParent (which is actually static) tracks which if any TabParent has IMEFocus
  // When the input mode is set to anything but IMEState::DISABLED,
  // mIMETabParent should be set to this
  mIMETabParent =
    aIMEEnabled != static_cast<int32_t>(IMEState::DISABLED) ? this : nullptr;
  nsCOMPtr<nsIWidget> widget = GetWidget();
  if (!widget || !AllowContentIME())
    return true;

  InputContext context;
  context.mIMEState.mEnabled = static_cast<IMEState::Enabled>(aIMEEnabled);
  context.mIMEState.mOpen = static_cast<IMEState::Open>(aIMEOpen);
  context.mHTMLInputType.Assign(aType);
  context.mHTMLInputInputmode.Assign(aInputmode);
  context.mActionHint.Assign(aActionHint);
  InputContextAction action(
    static_cast<InputContextAction::Cause>(aCause),
    static_cast<InputContextAction::FocusChange>(aFocusChange));
  widget->SetInputContext(context, action);

  nsCOMPtr<nsIObserverService> observerService = mozilla::services::GetObserverService();
  if (!observerService)
    return true;

  nsAutoString state;
  state.AppendInt(aIMEEnabled);
  observerService->NotifyObservers(nullptr, "ime-enabled-state-changed", state.get());

  return true;
}

bool
TabParent::RecvIsParentWindowMainWidgetVisible(bool* aIsVisible)
{
  nsCOMPtr<nsIContent> frame = do_QueryInterface(mFrameElement);
  if (!frame)
    return true;
  nsCOMPtr<nsIDOMWindowUtils> windowUtils =
    do_QueryInterface(frame->OwnerDoc()->GetWindow());
  nsresult rv = windowUtils->GetIsParentWindowMainWidgetVisible(aIsVisible);
  return NS_SUCCEEDED(rv);
}

bool
TabParent::RecvGetDPI(float* aValue)
{
  TryCacheDPIAndScale();

  NS_ABORT_IF_FALSE(mDPI > 0,
                    "Must not ask for DPI before OwnerElement is received!");
  *aValue = mDPI;
  return true;
}

bool
TabParent::RecvGetDefaultScale(double* aValue)
{
  TryCacheDPIAndScale();

  NS_ABORT_IF_FALSE(mDefaultScale.scale > 0,
                    "Must not ask for scale before OwnerElement is received!");
  *aValue = mDefaultScale.scale;
  return true;
}

bool
TabParent::RecvGetWidgetNativeData(WindowsHandle* aValue)
{
  nsCOMPtr<nsIContent> content = do_QueryInterface(mFrameElement);
  if (content) {
    nsIPresShell* shell = content->OwnerDoc()->GetShell();
    if (shell) {
      nsViewManager* vm = shell->GetViewManager();
      nsCOMPtr<nsIWidget> widget;
      vm->GetRootWidget(getter_AddRefs(widget));
      if (widget) {
        *aValue = reinterpret_cast<WindowsHandle>(
          widget->GetNativeData(NS_NATIVE_SHAREABLE_WINDOW));
        return true;
      }
    }
  }
  return false;
}

bool
TabParent::ReceiveMessage(const nsString& aMessage,
                          bool aSync,
                          const StructuredCloneData* aCloneData,
                          CpowHolder* aCpows,
                          nsIPrincipal* aPrincipal,
                          InfallibleTArray<nsString>* aJSONRetVal)
{
  nsRefPtr<nsFrameLoader> frameLoader = GetFrameLoader();
  if (frameLoader && frameLoader->GetFrameMessageManager()) {
    nsRefPtr<nsFrameMessageManager> manager =
      frameLoader->GetFrameMessageManager();

    manager->ReceiveMessage(mFrameElement,
                            aMessage,
                            aSync,
                            aCloneData,
                            aCpows,
                            aPrincipal,
                            aJSONRetVal);
  }
  return true;
}

// nsIAuthPromptProvider

// This method is largely copied from nsDocShell::GetAuthPrompt
NS_IMETHODIMP
TabParent::GetAuthPrompt(uint32_t aPromptReason, const nsIID& iid,
                          void** aResult)
{
  // we're either allowing auth, or it's a proxy request
  nsresult rv;
  nsCOMPtr<nsIPromptFactory> wwatch =
    do_GetService(NS_WINDOWWATCHER_CONTRACTID, &rv);
  NS_ENSURE_SUCCESS(rv, rv);

  nsCOMPtr<nsIDOMWindow> window;
  nsCOMPtr<nsIContent> frame = do_QueryInterface(mFrameElement);
  if (frame)
    window = do_QueryInterface(frame->OwnerDoc()->GetWindow());

  // Get an auth prompter for our window so that the parenting
  // of the dialogs works as it should when using tabs.
  nsCOMPtr<nsISupports> prompt;
  rv = wwatch->GetPrompt(window, iid, getter_AddRefs(prompt));
  NS_ENSURE_SUCCESS(rv, rv);

  nsCOMPtr<nsILoginManagerPrompter> prompter = do_QueryInterface(prompt);
  if (prompter) {
    nsCOMPtr<nsIDOMElement> browser = do_QueryInterface(mFrameElement);
    prompter->SetE10sData(browser, nullptr);
  }

  *aResult = prompt.forget().take();
  return NS_OK;
}

PColorPickerParent*
TabParent::AllocPColorPickerParent(const nsString& aTitle,
                                   const nsString& aInitialColor)
{
  return new ColorPickerParent(aTitle, aInitialColor);
}

bool
TabParent::DeallocPColorPickerParent(PColorPickerParent* actor)
{
  delete actor;
  return true;
}

PRenderFrameParent*
TabParent::AllocPRenderFrameParent()
{
  MOZ_ASSERT(ManagedPRenderFrameParent().IsEmpty());
  nsRefPtr<nsFrameLoader> frameLoader = GetFrameLoader();
  ScrollingBehavior scrolling = UseAsyncPanZoom() ? ASYNC_PAN_ZOOM : DEFAULT_SCROLLING;
  TextureFactoryIdentifier textureFactoryIdentifier;
  uint64_t layersId = 0;
  bool success = false;
  if(frameLoader) {
    PRenderFrameParent* renderFrame = 
      new RenderFrameParent(frameLoader,
                            scrolling,
                            &textureFactoryIdentifier,
                            &layersId,
                            &success);
    MOZ_ASSERT(success);
    return renderFrame;
  } else {
    return nullptr;
  }
}

bool
TabParent::DeallocPRenderFrameParent(PRenderFrameParent* aFrame)
{
  delete aFrame;
  return true;
}

bool
TabParent::RecvGetRenderFrameInfo(PRenderFrameParent* aRenderFrame,
                                  ScrollingBehavior* aScrolling,
                                  TextureFactoryIdentifier* aTextureFactoryIdentifier,
                                  uint64_t* aLayersId)
{
  RenderFrameParent* renderFrame = static_cast<RenderFrameParent*>(aRenderFrame);
  *aScrolling = renderFrame->UseAsyncPanZoom() ? ASYNC_PAN_ZOOM : DEFAULT_SCROLLING;
  renderFrame->GetTextureFactoryIdentifier(aTextureFactoryIdentifier);
  *aLayersId = renderFrame->GetLayersId();
  return true;
}

bool
TabParent::AllowContentIME()
{
  nsFocusManager* fm = nsFocusManager::GetFocusManager();
  NS_ENSURE_TRUE(fm, false);

  nsCOMPtr<nsIContent> focusedContent = fm->GetFocusedContent();
  if (focusedContent && focusedContent->IsEditable())
    return false;

  return true;
}

already_AddRefed<nsFrameLoader>
TabParent::GetFrameLoader() const
{
  nsCOMPtr<nsIFrameLoaderOwner> frameLoaderOwner = do_QueryInterface(mFrameElement);
  return frameLoaderOwner ? frameLoaderOwner->GetFrameLoader() : nullptr;
}

void
TabParent::TryCacheDPIAndScale()
{
  if (mDPI > 0) {
    return;
  }

  nsCOMPtr<nsIWidget> widget = GetWidget();

  if (!widget && mFrameElement) {
    // Even if we don't have a widget (e.g. because we're display:none), there's
    // probably a widget somewhere in the hierarchy our frame element lives in.
    widget = nsContentUtils::WidgetForDocument(mFrameElement->OwnerDoc());
  }

  if (widget) {
    mDPI = widget->GetDPI();
    mDefaultScale = widget->GetDefaultScale();
  }
}

already_AddRefed<nsIWidget>
TabParent::GetWidget() const
{
  nsCOMPtr<nsIContent> content = do_QueryInterface(mFrameElement);
  if (!content)
    return nullptr;

  nsIFrame *frame = content->GetPrimaryFrame();
  if (!frame)
    return nullptr;

  nsCOMPtr<nsIWidget> widget = frame->GetNearestWidget();
  return widget.forget();
}

bool
TabParent::UseAsyncPanZoom()
{
  bool usingOffMainThreadCompositing = !!CompositorParent::CompositorLoop();
  return (usingOffMainThreadCompositing && gfxPrefs::AsyncPanZoomEnabled() &&
          GetScrollingBehavior() == ASYNC_PAN_ZOOM);
}

nsEventStatus
TabParent::MaybeForwardEventToRenderFrame(WidgetInputEvent& aEvent,
                                          ScrollableLayerGuid* aOutTargetGuid,
                                          uint64_t* aOutInputBlockId)
{
  if (RenderFrameParent* rfp = GetRenderFrame()) {
    return rfp->NotifyInputEvent(aEvent, aOutTargetGuid, aOutInputBlockId);
  }
  return nsEventStatus_eIgnore;
}

bool
TabParent::RecvBrowserFrameOpenWindow(PBrowserParent* aOpener,
                                      const nsString& aURL,
                                      const nsString& aName,
                                      const nsString& aFeatures,
                                      bool* aOutWindowOpened)
{
  BrowserElementParent::OpenWindowResult opened =
    BrowserElementParent::OpenWindowOOP(static_cast<TabParent*>(aOpener),
                                        this, aURL, aName, aFeatures);
  *aOutWindowOpened = (opened != BrowserElementParent::OPEN_WINDOW_CANCELLED);
  return true;
}

bool
TabParent::RecvZoomToRect(const uint32_t& aPresShellId,
                          const ViewID& aViewId,
                          const CSSRect& aRect)
{
  if (RenderFrameParent* rfp = GetRenderFrame()) {
    rfp->ZoomToRect(aPresShellId, aViewId, aRect);
  }
  return true;
}

bool
TabParent::RecvUpdateZoomConstraints(const uint32_t& aPresShellId,
                                     const ViewID& aViewId,
                                     const bool& aIsRoot,
                                     const ZoomConstraints& aConstraints)
{
  if (RenderFrameParent* rfp = GetRenderFrame()) {
    rfp->UpdateZoomConstraints(aPresShellId, aViewId, aIsRoot, aConstraints);
  }
  return true;
}

bool
TabParent::RecvContentReceivedInputBlock(const ScrollableLayerGuid& aGuid,
                                         const uint64_t& aInputBlockId,
                                         const bool& aPreventDefault)
{
  if (RenderFrameParent* rfp = GetRenderFrame()) {
    rfp->ContentReceivedInputBlock(aGuid, aInputBlockId, aPreventDefault);
  }
  return true;
}

bool
TabParent::RecvSetTargetAPZC(const uint64_t& aInputBlockId,
                             const nsTArray<ScrollableLayerGuid>& aTargets)
{
  if (RenderFrameParent* rfp = GetRenderFrame()) {
    rfp->SetTargetAPZC(aInputBlockId, aTargets);
  }
  return true;
}

already_AddRefed<nsILoadContext>
TabParent::GetLoadContext()
{
  nsCOMPtr<nsILoadContext> loadContext;
  if (mLoadContext) {
    loadContext = mLoadContext;
  } else {
    loadContext = new LoadContext(GetOwnerElement(),
                                  OwnOrContainingAppId(),
                                  true /* aIsContent */,
                                  mChromeFlags & nsIWebBrowserChrome::CHROME_PRIVATE_WINDOW,
                                  mChromeFlags & nsIWebBrowserChrome::CHROME_REMOTE_WINDOW,
                                  IsBrowserElement());
    mLoadContext = loadContext;
  }
  return loadContext.forget();
}

/* Be careful if you call this method while proceding a real touch event. For
 * example sending a touchstart during a real touchend may results into
 * a busted mEventCaptureDepth and following touch events may not do what you
 * expect.
 */
NS_IMETHODIMP
TabParent::InjectTouchEvent(const nsAString& aType,
                            uint32_t* aIdentifiers,
                            int32_t* aXs,
                            int32_t* aYs,
                            uint32_t* aRxs,
                            uint32_t* aRys,
                            float* aRotationAngles,
                            float* aForces,
                            uint32_t aCount,
                            int32_t aModifiers)
{
  uint32_t msg;
  nsContentUtils::GetEventIdAndAtom(aType, eTouchEventClass, &msg);
  if (msg != NS_TOUCH_START && msg != NS_TOUCH_MOVE &&
      msg != NS_TOUCH_END && msg != NS_TOUCH_CANCEL) {
    return NS_ERROR_FAILURE;
  }

  nsCOMPtr<nsIWidget> widget = GetWidget();
  if (!widget) {
    return NS_ERROR_FAILURE;
  }

  WidgetTouchEvent event(true, msg, widget);
  event.modifiers = aModifiers;
  event.time = PR_IntervalNow();

  nsCOMPtr<nsIContent> content = do_QueryInterface(mFrameElement);
  if (!content || !content->OwnerDoc()) {
    return NS_ERROR_FAILURE;
  }

  nsIDocument* doc = content->OwnerDoc();
  if (!doc || !doc->GetShell()) {
    return NS_ERROR_FAILURE;
  }
  nsPresContext* presContext = doc->GetShell()->GetPresContext();

  event.touches.SetCapacity(aCount);
  for (uint32_t i = 0; i < aCount; ++i) {
    LayoutDeviceIntPoint pt =
      LayoutDeviceIntPoint::FromAppUnitsRounded(
        CSSPoint::ToAppUnits(CSSPoint(aXs[i], aYs[i])),
        presContext->AppUnitsPerDevPixel());

    nsRefPtr<Touch> t = new Touch(aIdentifiers[i],
                                  LayoutDeviceIntPoint::ToUntyped(pt),
                                  nsIntPoint(aRxs[i], aRys[i]),
                                  aRotationAngles[i],
                                  aForces[i]);

    // Consider all injected touch events as changedTouches. For more details
    // about the meaning of changedTouches for each event, see
    // https://developer.mozilla.org/docs/Web/API/TouchEvent.changedTouches
    t->mChanged = true;
    event.touches.AppendElement(t);
  }

  if ((msg == NS_TOUCH_END || msg == NS_TOUCH_CANCEL) && sEventCapturer) {
    WidgetGUIEvent* guiEvent = event.AsGUIEvent();
    TryCapture(*guiEvent);
  }

  SendRealTouchEvent(event);
  return NS_OK;
}

NS_IMETHODIMP
TabParent::GetUseAsyncPanZoom(bool* useAsyncPanZoom)
{
  *useAsyncPanZoom = UseAsyncPanZoom();
  return NS_OK;
}

NS_IMETHODIMP
TabParent::SetIsDocShellActive(bool isActive)
{
  unused << SendSetIsDocShellActive(isActive);
  return NS_OK;
}

bool
TabParent::RecvRemotePaintIsReady()
{
  nsCOMPtr<mozilla::dom::EventTarget> target = do_QueryInterface(mFrameElement);
  if (!target) {
    NS_WARNING("Could not locate target for MozAfterRemotePaint message.");
    return true;
  }

  nsCOMPtr<nsIDOMEvent> event;
  NS_NewDOMEvent(getter_AddRefs(event), mFrameElement, nullptr, nullptr);
  event->InitEvent(NS_LITERAL_STRING("MozAfterRemotePaint"), false, false);
  event->SetTrusted(true);
  event->GetInternalNSEvent()->mFlags.mOnlyChromeDispatch = true;
  bool dummy;
  mFrameElement->DispatchEvent(event, &dummy);
  return true;
}

mozilla::plugins::PPluginWidgetParent*
TabParent::AllocPPluginWidgetParent()
{
  return new mozilla::plugins::PluginWidgetParent();
}

bool
TabParent::DeallocPPluginWidgetParent(mozilla::plugins::PPluginWidgetParent* aActor)
{
  delete aActor;
  return true;
}

class FakeChannel MOZ_FINAL : public nsIChannel,
                              public nsIAuthPromptCallback,
                              public nsIInterfaceRequestor,
                              public nsILoadContext
{
public:
  FakeChannel(const nsCString& aUri, uint64_t aCallbackId, Element* aElement)
    : mCallbackId(aCallbackId)
    , mElement(aElement)
  {
    NS_NewURI(getter_AddRefs(mUri), aUri);
  }

  NS_DECL_ISUPPORTS
#define NO_IMPL { return NS_ERROR_NOT_IMPLEMENTED; }
  NS_IMETHOD GetName(nsACString&) NO_IMPL
  NS_IMETHOD IsPending(bool*) NO_IMPL
  NS_IMETHOD GetStatus(nsresult*) NO_IMPL
  NS_IMETHOD Cancel(nsresult) NO_IMPL
  NS_IMETHOD Suspend() NO_IMPL
  NS_IMETHOD Resume() NO_IMPL
  NS_IMETHOD GetLoadGroup(nsILoadGroup**) NO_IMPL
  NS_IMETHOD SetLoadGroup(nsILoadGroup*) NO_IMPL
  NS_IMETHOD SetLoadFlags(nsLoadFlags) NO_IMPL
  NS_IMETHOD GetLoadFlags(nsLoadFlags*) NO_IMPL
  NS_IMETHOD GetOriginalURI(nsIURI**) NO_IMPL
  NS_IMETHOD SetOriginalURI(nsIURI*) NO_IMPL
  NS_IMETHOD GetURI(nsIURI** aUri)
  {
    NS_IF_ADDREF(mUri);
    *aUri = mUri;
    return NS_OK;
  }
  NS_IMETHOD GetOwner(nsISupports**) NO_IMPL
  NS_IMETHOD SetOwner(nsISupports*) NO_IMPL
  NS_IMETHOD GetLoadInfo(nsILoadInfo** aLoadInfo)
  {
    NS_IF_ADDREF(*aLoadInfo = mLoadInfo);
    return NS_OK;
  }
  NS_IMETHOD SetLoadInfo(nsILoadInfo* aLoadInfo)
  {
    mLoadInfo = aLoadInfo;
    return NS_OK;
  }
  NS_IMETHOD GetNotificationCallbacks(nsIInterfaceRequestor** aRequestor)
  {
    NS_ADDREF(*aRequestor = this);
    return NS_OK;
  }
  NS_IMETHOD SetNotificationCallbacks(nsIInterfaceRequestor*) NO_IMPL
  NS_IMETHOD GetSecurityInfo(nsISupports**) NO_IMPL
  NS_IMETHOD GetContentType(nsACString&) NO_IMPL
  NS_IMETHOD SetContentType(const nsACString&) NO_IMPL
  NS_IMETHOD GetContentCharset(nsACString&) NO_IMPL
  NS_IMETHOD SetContentCharset(const nsACString&) NO_IMPL
  NS_IMETHOD GetContentLength(int64_t*) NO_IMPL
  NS_IMETHOD SetContentLength(int64_t) NO_IMPL
  NS_IMETHOD Open(nsIInputStream**) NO_IMPL
  NS_IMETHOD AsyncOpen(nsIStreamListener*, nsISupports*) NO_IMPL
  NS_IMETHOD GetContentDisposition(uint32_t*) NO_IMPL
  NS_IMETHOD SetContentDisposition(uint32_t) NO_IMPL
  NS_IMETHOD GetContentDispositionFilename(nsAString&) NO_IMPL
  NS_IMETHOD SetContentDispositionFilename(const nsAString&) NO_IMPL
  NS_IMETHOD GetContentDispositionHeader(nsACString&) NO_IMPL
  NS_IMETHOD OnAuthAvailable(nsISupports *aContext, nsIAuthInformation *aAuthInfo);
  NS_IMETHOD OnAuthCancelled(nsISupports *aContext, bool userCancel);
  NS_IMETHOD GetInterface(const nsIID & uuid, void **result)
  {
    return QueryInterface(uuid, result);
  }
  NS_IMETHOD GetAssociatedWindow(nsIDOMWindow**) NO_IMPL
  NS_IMETHOD GetTopWindow(nsIDOMWindow**) NO_IMPL
  NS_IMETHOD GetTopFrameElement(nsIDOMElement** aElement)
  {
    nsCOMPtr<nsIDOMElement> elem = do_QueryInterface(mElement);
    elem.forget(aElement);
    return NS_OK;
  }
  NS_IMETHOD GetNestedFrameId(uint64_t*) NO_IMPL
  NS_IMETHOD IsAppOfType(uint32_t, bool*) NO_IMPL
  NS_IMETHOD GetIsContent(bool*) NO_IMPL
  NS_IMETHOD GetUsePrivateBrowsing(bool*) NO_IMPL
  NS_IMETHOD SetUsePrivateBrowsing(bool) NO_IMPL
  NS_IMETHOD SetPrivateBrowsing(bool) NO_IMPL
  NS_IMETHOD GetIsInBrowserElement(bool*) NO_IMPL
  NS_IMETHOD GetAppId(uint32_t*) NO_IMPL
  NS_IMETHOD GetUseRemoteTabs(bool*) NO_IMPL
  NS_IMETHOD SetRemoteTabs(bool) NO_IMPL
#undef NO_IMPL

protected:
  ~FakeChannel() {}

  nsCOMPtr<nsIURI> mUri;
  uint64_t mCallbackId;
  nsCOMPtr<Element> mElement;
  nsCOMPtr<nsILoadInfo> mLoadInfo;
};

NS_IMPL_ISUPPORTS(FakeChannel, nsIChannel, nsIAuthPromptCallback,
                  nsIRequest, nsIInterfaceRequestor, nsILoadContext);

bool
TabParent::RecvAsyncAuthPrompt(const nsCString& aUri,
                               const nsString& aRealm,
                               const uint64_t& aCallbackId)
{
  nsCOMPtr<nsIAuthPrompt2> authPrompt;
  GetAuthPrompt(nsIAuthPromptProvider::PROMPT_NORMAL,
                NS_GET_IID(nsIAuthPrompt2),
                getter_AddRefs(authPrompt));
  nsRefPtr<FakeChannel> channel = new FakeChannel(aUri, aCallbackId, mFrameElement);
  uint32_t promptFlags = nsIAuthInformation::AUTH_HOST;

  nsRefPtr<nsAuthInformationHolder> holder =
    new nsAuthInformationHolder(promptFlags, aRealm,
                                EmptyCString());

  uint32_t level = nsIAuthPrompt2::LEVEL_NONE;
  nsCOMPtr<nsICancelable> dummy;
  nsresult rv =
    authPrompt->AsyncPromptAuth(channel, channel, nullptr,
                                level, holder, getter_AddRefs(dummy));

  return rv == NS_OK;
}

NS_IMETHODIMP
FakeChannel::OnAuthAvailable(nsISupports *aContext, nsIAuthInformation *aAuthInfo)
{
  nsAuthInformationHolder* holder =
    static_cast<nsAuthInformationHolder*>(aAuthInfo);

  if (!net::gNeckoChild->SendOnAuthAvailable(mCallbackId,
                                             holder->User(),
                                             holder->Password(),
                                             holder->Domain())) {
    return NS_ERROR_FAILURE;
  }
  return NS_OK;
}

NS_IMETHODIMP
FakeChannel::OnAuthCancelled(nsISupports *aContext, bool userCancel)
{
  if (!net::gNeckoChild->SendOnAuthCancelled(mCallbackId, userCancel)) {
    return NS_ERROR_FAILURE;
  }
  return NS_OK;
}


} // namespace tabs
} // namespace mozilla
