/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*-
 * vim: set ts=8 sts=4 et sw=4 tw=99:
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * JS SIMD pseudo-module.
 * Specification matches polyfill:
 * https://github.com/johnmccutchan/ecmascript_simd/blob/master/src/ecmascript_simd.js
 * The objects float32x4 and int32x4 are installed on the SIMD pseudo-module.
 */

#include "builtin/SIMD.h"

#include "jsapi.h"
#include "jsfriendapi.h"

#include "builtin/TypedObject.h"
#include "js/Value.h"

#include "jsobjinlines.h"

using namespace js;

using mozilla::ArrayLength;
using mozilla::IsFinite;
using mozilla::IsNaN;
using mozilla::FloorLog2;

namespace js {
extern const JSFunctionSpec Float32x4Methods[];
extern const JSFunctionSpec Int32x4Methods[];
}

///////////////////////////////////////////////////////////////////////////
// SIMD

static const char *laneNames[] = {"lane 0", "lane 1", "lane 2", "lane3"};

static bool
CheckVectorObject(HandleValue v, SimdTypeDescr::Type expectedType)
{
    if (!v.isObject())
        return false;

    JSObject &obj = v.toObject();
    if (!obj.is<TypedObject>())
        return false;

    TypeDescr &typeRepr = obj.as<TypedObject>().typeDescr();
    if (typeRepr.kind() != type::Simd)
        return false;

    return typeRepr.as<SimdTypeDescr>().type() == expectedType;
}

template<class V>
bool
js::IsVectorObject(HandleValue v)
{
    return CheckVectorObject(v, V::type);
}

template bool js::IsVectorObject<Int32x4>(HandleValue v);
template bool js::IsVectorObject<Float32x4>(HandleValue v);

template<typename V>
bool
js::ToSimdConstant(JSContext *cx, HandleValue v, jit::SimdConstant *out)
{
    typedef typename V::Elem Elem;
    if (!IsVectorObject<V>(v)) {
        JS_ReportErrorNumber(cx, js_GetErrorMessage, nullptr, JSMSG_SIMD_NOT_A_VECTOR);
        return false;
    }

    Elem *mem = reinterpret_cast<Elem *>(v.toObject().as<TypedObject>().typedMem());
    *out = jit::SimdConstant::CreateX4(mem);
    return true;
}

template bool js::ToSimdConstant<Int32x4>(JSContext *cx, HandleValue v, jit::SimdConstant *out);
template bool js::ToSimdConstant<Float32x4>(JSContext *cx, HandleValue v, jit::SimdConstant *out);

template<typename Elem>
static Elem
TypedObjectMemory(HandleValue v)
{
    TypedObject &obj = v.toObject().as<TypedObject>();
    return reinterpret_cast<Elem>(obj.typedMem());
}

template<typename SimdType, int lane>
static bool GetSimdLane(JSContext *cx, unsigned argc, Value *vp)
{
    typedef typename SimdType::Elem Elem;

    CallArgs args = CallArgsFromVp(argc, vp);
    if (!IsVectorObject<SimdType>(args.thisv())) {
        JS_ReportErrorNumber(cx, js_GetErrorMessage, nullptr, JSMSG_INCOMPATIBLE_PROTO,
                             SimdTypeDescr::class_.name, laneNames[lane],
                             InformalValueTypeName(args.thisv()));
        return false;
    }

    Elem *data = TypedObjectMemory<Elem *>(args.thisv());
    SimdType::setReturn(args, data[lane]);
    return true;
}

#define LANE_ACCESSOR(type, lane) \
static bool type##Lane##lane(JSContext *cx, unsigned argc, Value *vp) { \
    return GetSimdLane<type, lane>(cx, argc, vp);\
}

#define FOUR_LANES_ACCESSOR(type) \
    LANE_ACCESSOR(type, 0); \
    LANE_ACCESSOR(type, 1); \
    LANE_ACCESSOR(type, 2); \
    LANE_ACCESSOR(type, 3);

    FOUR_LANES_ACCESSOR(Int32x4);
    FOUR_LANES_ACCESSOR(Float32x4);
#undef FOUR_LANES_ACCESSOR
#undef LANE_ACCESSOR

template<typename SimdType>
static bool SignMask(JSContext *cx, unsigned argc, Value *vp)
{
    typedef typename SimdType::Elem Elem;

    CallArgs args = CallArgsFromVp(argc, vp);
    if (!args.thisv().isObject() || !args.thisv().toObject().is<TypedObject>()) {
        JS_ReportErrorNumber(cx, js_GetErrorMessage, nullptr, JSMSG_INCOMPATIBLE_PROTO,
                             SimdTypeDescr::class_.name, "signMask",
                             InformalValueTypeName(args.thisv()));
        return false;
    }

    TypedObject &typedObj = args.thisv().toObject().as<TypedObject>();
    TypeDescr &descr = typedObj.typeDescr();
    if (descr.kind() != type::Simd || descr.as<SimdTypeDescr>().type() != SimdType::type) {
        JS_ReportErrorNumber(cx, js_GetErrorMessage, nullptr, JSMSG_INCOMPATIBLE_PROTO,
                             SimdTypeDescr::class_.name, "signMask",
                             InformalValueTypeName(args.thisv()));
        return false;
    }

    Elem *data = reinterpret_cast<Elem *>(typedObj.typedMem());
    int32_t mx = data[0] < 0.0 ? 1 : 0;
    int32_t my = data[1] < 0.0 ? 1 : 0;
    int32_t mz = data[2] < 0.0 ? 1 : 0;
    int32_t mw = data[3] < 0.0 ? 1 : 0;
    int32_t result = mx | my << 1 | mz << 2 | mw << 3;
    args.rval().setInt32(result);
    return true;
}

#define SIGN_MASK(type) \
static bool type##SignMask(JSContext *cx, unsigned argc, Value *vp) { \
    return SignMask<type>(cx, argc, vp); \
}
    SIGN_MASK(Float32x4);
    SIGN_MASK(Int32x4);
#undef SIGN_MASK

const Class SimdTypeDescr::class_ = {
    "SIMD",
    JSCLASS_HAS_RESERVED_SLOTS(JS_DESCR_SLOTS) | JSCLASS_BACKGROUND_FINALIZE,
    nullptr, /* addProperty */
    nullptr, /* delProperty */
    nullptr, /* getProperty */
    nullptr, /* setProperty */
    nullptr, /* enumerate */
    nullptr, /* resolve */
    nullptr, /* convert */
    TypeDescr::finalize,
    call
};

// These classes just exist to group together various properties and so on.
namespace js {
class Int32x4Defn {
  public:
    static const SimdTypeDescr::Type type = SimdTypeDescr::TYPE_INT32;
    static const JSFunctionSpec TypeDescriptorMethods[];
    static const JSPropertySpec TypedObjectProperties[];
    static const JSFunctionSpec TypedObjectMethods[];
};
class Float32x4Defn {
  public:
    static const SimdTypeDescr::Type type = SimdTypeDescr::TYPE_FLOAT32;
    static const JSFunctionSpec TypeDescriptorMethods[];
    static const JSPropertySpec TypedObjectProperties[];
    static const JSFunctionSpec TypedObjectMethods[];
};
} // namespace js

const JSFunctionSpec js::Float32x4Defn::TypeDescriptorMethods[] = {
    JS_SELF_HOSTED_FN("toSource", "DescrToSource", 0, 0),
    JS_SELF_HOSTED_FN("array", "ArrayShorthand", 1, 0),
    JS_SELF_HOSTED_FN("equivalent", "TypeDescrEquivalent", 1, 0),
    JS_FS_END
};

const JSPropertySpec js::Float32x4Defn::TypedObjectProperties[] = {
    JS_PSG("x", Float32x4Lane0, JSPROP_PERMANENT),
    JS_PSG("y", Float32x4Lane1, JSPROP_PERMANENT),
    JS_PSG("z", Float32x4Lane2, JSPROP_PERMANENT),
    JS_PSG("w", Float32x4Lane3, JSPROP_PERMANENT),
    JS_PSG("signMask", Float32x4SignMask, JSPROP_PERMANENT),
    JS_PS_END
};

const JSFunctionSpec js::Float32x4Defn::TypedObjectMethods[] = {
    JS_SELF_HOSTED_FN("toSource", "SimdToSource", 0, 0),
    JS_FS_END
};

const JSFunctionSpec js::Int32x4Defn::TypeDescriptorMethods[] = {
    JS_SELF_HOSTED_FN("toSource", "DescrToSource", 0, 0),
    JS_SELF_HOSTED_FN("array", "ArrayShorthand", 1, 0),
    JS_SELF_HOSTED_FN("equivalent", "TypeDescrEquivalent", 1, 0),
    JS_FS_END,
};

const JSPropertySpec js::Int32x4Defn::TypedObjectProperties[] = {
    JS_PSG("x", Int32x4Lane0, JSPROP_PERMANENT),
    JS_PSG("y", Int32x4Lane1, JSPROP_PERMANENT),
    JS_PSG("z", Int32x4Lane2, JSPROP_PERMANENT),
    JS_PSG("w", Int32x4Lane3, JSPROP_PERMANENT),
    JS_PSG("signMask", Int32x4SignMask, JSPROP_PERMANENT),
    JS_PS_END
};

const JSFunctionSpec js::Int32x4Defn::TypedObjectMethods[] = {
    JS_SELF_HOSTED_FN("toSource", "SimdToSource", 0, 0),
    JS_FS_END
};

template<typename T>
static JSObject *
CreateSimdClass(JSContext *cx,
              Handle<GlobalObject*> global,
              HandlePropertyName stringRepr)
{
    const SimdTypeDescr::Type type = T::type;

    RootedObject funcProto(cx, global->getOrCreateFunctionPrototype(cx));
    if (!funcProto)
        return nullptr;

    // Create type constructor itself and initialize its reserved slots.

    Rooted<SimdTypeDescr*> typeDescr(cx);
    typeDescr = NewObjectWithProto<SimdTypeDescr>(cx, funcProto, global, TenuredObject);
    if (!typeDescr)
        return nullptr;

    typeDescr->initReservedSlot(JS_DESCR_SLOT_KIND, Int32Value(type::Simd));
    typeDescr->initReservedSlot(JS_DESCR_SLOT_STRING_REPR, StringValue(stringRepr));
    typeDescr->initReservedSlot(JS_DESCR_SLOT_ALIGNMENT, Int32Value(SimdTypeDescr::alignment(type)));
    typeDescr->initReservedSlot(JS_DESCR_SLOT_SIZE, Int32Value(SimdTypeDescr::size(type)));
    typeDescr->initReservedSlot(JS_DESCR_SLOT_OPAQUE, BooleanValue(false));
    typeDescr->initReservedSlot(JS_DESCR_SLOT_TYPE, Int32Value(T::type));
    typeDescr->initReservedSlot(JS_DESCR_SLOT_TRACE_LIST, PrivateValue(nullptr));

    if (!CreateUserSizeAndAlignmentProperties(cx, typeDescr))
        return nullptr;

    // Create prototype property, which inherits from Object.prototype.

    RootedObject objProto(cx, global->getOrCreateObjectPrototype(cx));
    if (!objProto)
        return nullptr;
    Rooted<TypedProto*> proto(cx);
    proto = NewObjectWithProto<TypedProto>(cx, objProto, nullptr, TenuredObject);
    if (!proto)
        return nullptr;
    proto->initTypeDescrSlot(*typeDescr);
    typeDescr->initReservedSlot(JS_DESCR_SLOT_TYPROTO, ObjectValue(*proto));

    // Link constructor to prototype and install properties.

    if (!JS_DefineFunctions(cx, typeDescr, T::TypeDescriptorMethods))
        return nullptr;

    if (!LinkConstructorAndPrototype(cx, typeDescr, proto) ||
        !DefinePropertiesAndFunctions(cx, proto, T::TypedObjectProperties,
                                      T::TypedObjectMethods))
    {
        return nullptr;
    }

    return typeDescr;
}

bool
SimdTypeDescr::call(JSContext *cx, unsigned argc, Value *vp)
{
    CallArgs args = CallArgsFromVp(argc, vp);
    const unsigned LANES = 4;

    Rooted<SimdTypeDescr*> descr(cx, &args.callee().as<SimdTypeDescr>());
    if (args.length() == 1) {
        // SIMD type used as a coercion
        if (!CheckVectorObject(args[0], descr->type())) {
            JS_ReportErrorNumber(cx, js_GetErrorMessage, nullptr, JSMSG_SIMD_NOT_A_VECTOR);
            return false;
        }

        args.rval().setObject(args[0].toObject());
        return true;
    }

    if (args.length() < LANES) {
        JS_ReportErrorNumber(cx, js_GetErrorMessage, nullptr, JSMSG_MORE_ARGS_NEEDED,
                             args.callee().getClass()->name, "3", "s");
        return false;
    }

    Rooted<TypedObject*> result(cx, TypedObject::createZeroed(cx, descr, 0));
    if (!result)
        return false;

    switch (descr->type()) {
      case SimdTypeDescr::TYPE_INT32: {
        int32_t *mem = reinterpret_cast<int32_t*>(result->typedMem());
        for (unsigned i = 0; i < 4; i++) {
            if (!ToInt32(cx, args[i], &mem[i]))
                return false;
        }
        break;
      }
      case SimdTypeDescr::TYPE_FLOAT32: {
        float *mem = reinterpret_cast<float*>(result->typedMem());
        for (unsigned i = 0; i < 4; i++) {
            if (!RoundFloat32(cx, args[i], &mem[i]))
                return false;
        }
        break;
      }
    }
    args.rval().setObject(*result);
    return true;
}

///////////////////////////////////////////////////////////////////////////
// SIMD class

const Class SIMDObject::class_ = {
    "SIMD",
    JSCLASS_HAS_CACHED_PROTO(JSProto_SIMD)
};

JSObject *
SIMDObject::initClass(JSContext *cx, Handle<GlobalObject *> global)
{
    // SIMD relies on having the TypedObject module initialized.
    // In particular, the self-hosted code for array() wants
    // to be able to call GetTypedObjectModule(). It is NOT necessary
    // to install the TypedObjectModule global, but at the moment
    // those two things are not separable.
    if (!global->getOrCreateTypedObjectModule(cx))
        return nullptr;

    // Create SIMD Object.
    RootedObject objProto(cx, global->getOrCreateObjectPrototype(cx));
    if (!objProto)
        return nullptr;
    RootedObject SIMD(cx, NewObjectWithGivenProto(cx, &SIMDObject::class_, objProto,
                                                  global, SingletonObject));
    if (!SIMD)
        return nullptr;

    // float32x4
    RootedObject float32x4Object(cx);
    float32x4Object = CreateSimdClass<Float32x4Defn>(cx, global,
                                                     cx->names().float32x4);
    if (!float32x4Object)
        return nullptr;

    // Define float32x4 functions and install as a property of the SIMD object.
    RootedValue float32x4Value(cx, ObjectValue(*float32x4Object));
    if (!JS_DefineFunctions(cx, float32x4Object, Float32x4Methods) ||
        !JSObject::defineProperty(cx, SIMD, cx->names().float32x4,
                                  float32x4Value, nullptr, nullptr,
                                  JSPROP_READONLY | JSPROP_PERMANENT))
    {
        return nullptr;
    }

    // int32x4
    RootedObject int32x4Object(cx);
    int32x4Object = CreateSimdClass<Int32x4Defn>(cx, global,
                                                 cx->names().int32x4);
    if (!int32x4Object)
        return nullptr;

    // Define int32x4 functions and install as a property of the SIMD object.
    RootedValue int32x4Value(cx, ObjectValue(*int32x4Object));
    if (!JS_DefineFunctions(cx, int32x4Object, Int32x4Methods) ||
        !JSObject::defineProperty(cx, SIMD, cx->names().int32x4,
                                  int32x4Value, nullptr, nullptr,
                                  JSPROP_READONLY | JSPROP_PERMANENT))
    {
        return nullptr;
    }

    RootedValue SIMDValue(cx, ObjectValue(*SIMD));

    // Everything is set up, install SIMD on the global object.
    if (!JSObject::defineProperty(cx, global, cx->names().SIMD, SIMDValue, nullptr, nullptr, 0))
        return nullptr;

    global->setConstructor(JSProto_SIMD, SIMDValue);
    global->setFloat32x4TypeDescr(*float32x4Object);
    global->setInt32x4TypeDescr(*int32x4Object);
    return SIMD;
}

JSObject *
js_InitSIMDClass(JSContext *cx, HandleObject obj)
{
    MOZ_ASSERT(obj->is<GlobalObject>());
    Rooted<GlobalObject *> global(cx, &obj->as<GlobalObject>());
    return SIMDObject::initClass(cx, global);
}

template<typename V>
JSObject *
js::CreateSimd(JSContext *cx, typename V::Elem *data)
{
    typedef typename V::Elem Elem;
    Rooted<TypeDescr*> typeDescr(cx, &V::GetTypeDescr(*cx->global()));
    MOZ_ASSERT(typeDescr);

    Rooted<TypedObject *> result(cx, TypedObject::createZeroed(cx, typeDescr, 0));
    if (!result)
        return nullptr;

    Elem *resultMem = reinterpret_cast<Elem *>(result->typedMem());
    memcpy(resultMem, data, sizeof(Elem) * V::lanes);
    return result;
}

template JSObject *js::CreateSimd<Float32x4>(JSContext *cx, Float32x4::Elem *data);
template JSObject *js::CreateSimd<Int32x4>(JSContext *cx, Int32x4::Elem *data);

namespace js {
// Unary SIMD operators
template<typename T>
struct Abs {
    static inline T apply(T x) { return mozilla::Abs(x); }
};
template<typename T>
struct Neg {
    static inline T apply(T x) { return -1 * x; }
};
template<typename T>
struct Not {
    static inline T apply(T x) { return ~x; }
};
template<typename T>
struct Rec {
    static inline T apply(T x) { return 1 / x; }
};
template<typename T>
struct RecSqrt {
    static inline T apply(T x) { return 1 / sqrt(x); }
};
template<typename T>
struct Sqrt {
    static inline T apply(T x) { return sqrt(x); }
};

// Binary SIMD operators
template<typename T>
struct Add {
    static inline T apply(T l, T r) { return l + r; }
};
template<typename T>
struct Sub {
    static inline T apply(T l, T r) { return l - r; }
};
template<typename T>
struct Div {
    static inline T apply(T l, T r) { return l / r; }
};
template<typename T>
struct Mul {
    static inline T apply(T l, T r) { return l * r; }
};
template<typename T>
struct Minimum {
    static inline T apply(T l, T r) { return math_min_impl(l, r); }
};
template<typename T>
struct MinNum {
    static inline T apply(T l, T r) { return IsNaN(l) ? r : (IsNaN(r) ? l : math_min_impl(l, r)); }
};
template<typename T>
struct Maximum {
    static inline T apply(T l, T r) { return math_max_impl(l, r); }
};
template<typename T>
struct MaxNum {
    static inline T apply(T l, T r) { return IsNaN(l) ? r : (IsNaN(r) ? l : math_max_impl(l, r)); }
};
template<typename T>
struct LessThan {
    static inline int32_t apply(T l, T r) { return l < r ? 0xFFFFFFFF : 0x0; }
};
template<typename T>
struct LessThanOrEqual {
    static inline int32_t apply(T l, T r) { return l <= r ? 0xFFFFFFFF : 0x0; }
};
template<typename T>
struct GreaterThan {
    static inline int32_t apply(T l, T r) { return l > r ? 0xFFFFFFFF : 0x0; }
};
template<typename T>
struct GreaterThanOrEqual {
    static inline int32_t apply(T l, T r) { return l >= r ? 0xFFFFFFFF : 0x0; }
};
template<typename T>
struct Equal {
    static inline int32_t apply(T l, T r) { return l == r ? 0xFFFFFFFF : 0x0; }
};
template<typename T>
struct NotEqual {
    static inline int32_t apply(T l, T r) { return l != r ? 0xFFFFFFFF : 0x0; }
};
template<typename T>
struct Xor {
    static inline T apply(T l, T r) { return l ^ r; }
};
template<typename T>
struct And {
    static inline T apply(T l, T r) { return l & r; }
};
template<typename T>
struct Or {
    static inline T apply(T l, T r) { return l | r; }
};
template<typename T>
struct WithX {
    static inline T apply(int32_t lane, T scalar, T x) { return lane == 0 ? scalar : x; }
};
template<typename T>
struct WithY {
    static inline T apply(int32_t lane, T scalar, T x) { return lane == 1 ? scalar : x; }
};
template<typename T>
struct WithZ {
    static inline T apply(int32_t lane, T scalar, T x) { return lane == 2 ? scalar : x; }
};
template<typename T>
struct WithW {
    static inline T apply(int32_t lane, T scalar, T x) { return lane == 3 ? scalar : x; }
};
struct ShiftLeft {
    static inline int32_t apply(int32_t v, int32_t bits) { return v << bits; }
};
struct ShiftRight {
    static inline int32_t apply(int32_t v, int32_t bits) { return v >> bits; }
};
struct ShiftRightLogical {
    static inline int32_t apply(int32_t v, int32_t bits) { return uint32_t(v) >> (bits & 31); }
};
}

static inline bool
ErrorBadArgs(JSContext *cx)
{
    JS_ReportErrorNumber(cx, js_GetErrorMessage, nullptr, JSMSG_TYPED_ARRAY_BAD_ARGS);
    return false;
}

template<typename Out>
static bool
StoreResult(JSContext *cx, CallArgs &args, typename Out::Elem *result)
{
    RootedObject obj(cx, CreateSimd<Out>(cx, result));
    if (!obj)
        return false;
    args.rval().setObject(*obj);
    return true;
}

// Coerces the inputs of type In to the type Coercion, apply the operator Op
// and converts the result to the type Out.
template<typename In, typename Coercion, template<typename C> class Op, typename Out>
static bool
CoercedUnaryFunc(JSContext *cx, unsigned argc, Value *vp)
{
    typedef typename Coercion::Elem CoercionElem;
    typedef typename Out::Elem RetElem;

    CallArgs args = CallArgsFromVp(argc, vp);
    if (args.length() != 1 || !IsVectorObject<In>(args[0]))
        return ErrorBadArgs(cx);

    CoercionElem result[Coercion::lanes];
    CoercionElem *val = TypedObjectMemory<CoercionElem *>(args[0]);
    for (unsigned i = 0; i < Coercion::lanes; i++)
        result[i] = Op<CoercionElem>::apply(val[i]);
    return StoreResult<Out>(cx, args, (RetElem*) result);
}

// Coerces the inputs of type In to the type Coercion, apply the operator Op
// and converts the result to the type Out.
template<typename In, typename Coercion, template<typename C> class Op, typename Out>
static bool
CoercedBinaryFunc(JSContext *cx, unsigned argc, Value *vp)
{
    typedef typename Coercion::Elem CoercionElem;
    typedef typename Out::Elem RetElem;

    CallArgs args = CallArgsFromVp(argc, vp);
    if (args.length() != 2 || !IsVectorObject<In>(args[0]) || !IsVectorObject<In>(args[1]))
        return ErrorBadArgs(cx);

    CoercionElem result[Coercion::lanes];
    CoercionElem *left = TypedObjectMemory<CoercionElem *>(args[0]);
    CoercionElem *right = TypedObjectMemory<CoercionElem *>(args[1]);
    for (unsigned i = 0; i < Coercion::lanes; i++)
        result[i] = Op<CoercionElem>::apply(left[i], right[i]);
    return StoreResult<Out>(cx, args, (RetElem *) result);
}

// Same as above, with no coercion, i.e. Coercion == In.
template<typename In, template<typename C> class Op, typename Out>
static bool
UnaryFunc(JSContext *cx, unsigned argc, Value *vp)
{
    return CoercedUnaryFunc<In, Out, Op, Out>(cx, argc, vp);
}

template<typename In, template<typename C> class Op, typename Out>
static bool
BinaryFunc(JSContext *cx, unsigned argc, Value *vp)
{
    return CoercedBinaryFunc<In, Out, Op, Out>(cx, argc, vp);
}

template<typename V, template<typename T> class OpWith>
static bool
FuncWith(JSContext *cx, unsigned argc, Value *vp)
{
    typedef typename V::Elem Elem;

    CallArgs args = CallArgsFromVp(argc, vp);
    if (args.length() != 2 || !IsVectorObject<V>(args[0]) ||
        (!args[1].isNumber() && !args[1].isBoolean()))
    {
        return ErrorBadArgs(cx);
    }

    Elem *val = TypedObjectMemory<Elem *>(args[0]);
    Elem result[V::lanes];

    if (args[1].isNumber()) {
        Elem withAsNumber;
        if (!V::toType(cx, args[1], &withAsNumber))
            return false;
        for (unsigned i = 0; i < V::lanes; i++)
            result[i] = OpWith<Elem>::apply(i, withAsNumber, val[i]);
    } else {
        MOZ_ASSERT(args[1].isBoolean());
        bool withAsBool = args[1].toBoolean();
        for (unsigned i = 0; i < V::lanes; i++)
            result[i] = OpWith<Elem>::apply(i, withAsBool, val[i]);
    }
    return StoreResult<V>(cx, args, result);
}

template<typename V>
static bool
Swizzle(JSContext *cx, unsigned argc, Value *vp)
{
    typedef typename V::Elem Elem;

    CallArgs args = CallArgsFromVp(argc, vp);
    if (args.length() != (V::lanes + 1) || !IsVectorObject<V>(args[0]))
        return ErrorBadArgs(cx);

    uint32_t lanes[V::lanes];
    for (unsigned i = 0; i < V::lanes; i++) {
        int32_t lane = -1;
        if (!ToInt32(cx, args[i + 1], &lane))
            return false;
        if (lane < 0 || uint32_t(lane) >= V::lanes)
            return ErrorBadArgs(cx);
        lanes[i] = uint32_t(lane);
    }

    Elem *val = TypedObjectMemory<Elem *>(args[0]);

    Elem result[V::lanes];
    for (unsigned i = 0; i < V::lanes; i++)
        result[i] = val[lanes[i]];

    return StoreResult<V>(cx, args, result);
}

template<typename V>
static bool
Shuffle(JSContext *cx, unsigned argc, Value *vp)
{
    typedef typename V::Elem Elem;

    CallArgs args = CallArgsFromVp(argc, vp);
    if (args.length() != (V::lanes + 2) || !IsVectorObject<V>(args[0]) || !IsVectorObject<V>(args[1]))
        return ErrorBadArgs(cx);

    uint32_t lanes[V::lanes];
    for (unsigned i = 0; i < V::lanes; i++) {
        int32_t lane = -1;
        if (!ToInt32(cx, args[i + 2], &lane))
            return false;
        if (lane < 0 || uint32_t(lane) >= (2 * V::lanes))
            return ErrorBadArgs(cx);
        lanes[i] = uint32_t(lane);
    }

    Elem *lhs = TypedObjectMemory<Elem *>(args[0]);
    Elem *rhs = TypedObjectMemory<Elem *>(args[1]);

    Elem result[V::lanes];
    for (unsigned i = 0; i < V::lanes; i++) {
        Elem *selectedInput = lanes[i] < V::lanes ? lhs : rhs;
        result[i] = selectedInput[lanes[i] % V::lanes];
    }

    return StoreResult<V>(cx, args, result);
}

template<typename Op>
static bool
Int32x4BinaryScalar(JSContext *cx, unsigned argc, Value *vp)
{
    CallArgs args = CallArgsFromVp(argc, vp);
    if (args.length() != 2)
        return ErrorBadArgs(cx);

    int32_t result[4];
    if (!IsVectorObject<Int32x4>(args[0]) || !args[1].isNumber())
        return ErrorBadArgs(cx);

    int32_t *val = TypedObjectMemory<int32_t *>(args[0]);
    int32_t bits;
    if (!ToInt32(cx, args[1], &bits))
        return false;

    for (unsigned i = 0; i < 4; i++)
        result[i] = Op::apply(val[i], bits);
    return StoreResult<Int32x4>(cx, args, result);
}

template<typename In, template<typename C> class Op>
static bool
CompareFunc(JSContext *cx, unsigned argc, Value *vp)
{
    typedef typename In::Elem InElem;

    CallArgs args = CallArgsFromVp(argc, vp);
    if (args.length() != 2 || !IsVectorObject<In>(args[0]) || !IsVectorObject<In>(args[1]))
        return ErrorBadArgs(cx);

    int32_t result[Int32x4::lanes];
    InElem *left = TypedObjectMemory<InElem *>(args[0]);
    InElem *right = TypedObjectMemory<InElem *>(args[1]);
    for (unsigned i = 0; i < Int32x4::lanes; i++)
        result[i] = Op<InElem>::apply(left[i], right[i]);

    return StoreResult<Int32x4>(cx, args, result);
}

template<typename V, typename Vret>
static bool
FuncConvert(JSContext *cx, unsigned argc, Value *vp)
{
    typedef typename V::Elem Elem;
    typedef typename Vret::Elem RetElem;

    CallArgs args = CallArgsFromVp(argc, vp);
    if (args.length() != 1 || !IsVectorObject<V>(args[0]))
        return ErrorBadArgs(cx);

    Elem *val = TypedObjectMemory<Elem *>(args[0]);
    RetElem result[Vret::lanes];
    for (unsigned i = 0; i < Vret::lanes; i++)
        result[i] = ConvertScalar<RetElem>(val[i]);
    return StoreResult<Vret>(cx, args, result);
}

template<typename V, typename Vret>
static bool
FuncConvertBits(JSContext *cx, unsigned argc, Value *vp)
{
    typedef typename Vret::Elem RetElem;

    CallArgs args = CallArgsFromVp(argc, vp);
    if (args.length() != 1 || !IsVectorObject<V>(args[0]))
        return ErrorBadArgs(cx);

    RetElem *result = TypedObjectMemory<RetElem *>(args[0]);
    return StoreResult<Vret>(cx, args, result);
}

template<typename Vret>
static bool
FuncZero(JSContext *cx, unsigned argc, Value *vp)
{
    typedef typename Vret::Elem RetElem;

    CallArgs args = CallArgsFromVp(argc, vp);
    if (args.length() != 0)
        return ErrorBadArgs(cx);

    RetElem result[Vret::lanes];
    for (unsigned i = 0; i < Vret::lanes; i++)
        result[i] = RetElem(0);
    return StoreResult<Vret>(cx, args, result);
}

template<typename Vret>
static bool
FuncSplat(JSContext *cx, unsigned argc, Value *vp)
{
    typedef typename Vret::Elem RetElem;

    CallArgs args = CallArgsFromVp(argc, vp);
    if (args.length() != 1 || !args[0].isNumber())
        return ErrorBadArgs(cx);

    RetElem arg;
    if (!Vret::toType(cx, args[0], &arg))
        return false;

    RetElem result[Vret::lanes];
    for (unsigned i = 0; i < Vret::lanes; i++)
        result[i] = arg;
    return StoreResult<Vret>(cx, args, result);
}

static bool
Int32x4Bool(JSContext *cx, unsigned argc, Value *vp)
{
    CallArgs args = CallArgsFromVp(argc, vp);
    if (args.length() != 4 ||
        !args[0].isBoolean() || !args[1].isBoolean() ||
        !args[2].isBoolean() || !args[3].isBoolean())
    {
        return ErrorBadArgs(cx);
    }

    int32_t result[Int32x4::lanes];
    for (unsigned i = 0; i < Int32x4::lanes; i++)
        result[i] = args[i].toBoolean() ? 0xFFFFFFFF : 0x0;
    return StoreResult<Int32x4>(cx, args, result);
}

static bool
Float32x4Clamp(JSContext *cx, unsigned argc, Value *vp)
{
    CallArgs args = CallArgsFromVp(argc, vp);
    if (args.length() != 3 || !IsVectorObject<Float32x4>(args[0]) ||
        !IsVectorObject<Float32x4>(args[1]) || !IsVectorObject<Float32x4>(args[2]))
    {
        return ErrorBadArgs(cx);
    }

    float *val = TypedObjectMemory<float *>(args[0]);
    float *lowerLimit = TypedObjectMemory<float *>(args[1]);
    float *upperLimit = TypedObjectMemory<float *>(args[2]);

    float result[Float32x4::lanes];
    for (unsigned i = 0; i < Float32x4::lanes; i++) {
        result[i] = val[i] < lowerLimit[i] ? lowerLimit[i] : val[i];
        result[i] = result[i] > upperLimit[i] ? upperLimit[i] : result[i];
    }

    return StoreResult<Float32x4>(cx, args, result);
}

static bool
Int32x4Select(JSContext *cx, unsigned argc, Value *vp)
{
    CallArgs args = CallArgsFromVp(argc, vp);
    if (args.length() != 3 || !IsVectorObject<Int32x4>(args[0]) ||
        !IsVectorObject<Int32x4>(args[1]) || !IsVectorObject<Int32x4>(args[2]))
    {
        return ErrorBadArgs(cx);
    }

    int32_t *val = TypedObjectMemory<int32_t *>(args[0]);
    int32_t *tv = TypedObjectMemory<int32_t *>(args[1]);
    int32_t *fv = TypedObjectMemory<int32_t *>(args[2]);

    int32_t tr[Int32x4::lanes];
    for (unsigned i = 0; i < Int32x4::lanes; i++)
        tr[i] = And<int32_t>::apply(val[i], tv[i]);

    int32_t fr[Int32x4::lanes];
    for (unsigned i = 0; i < Int32x4::lanes; i++)
        fr[i] = And<int32_t>::apply(Not<int32_t>::apply(val[i]), fv[i]);

    int32_t orInt[Int32x4::lanes];
    for (unsigned i = 0; i < Int32x4::lanes; i++)
        orInt[i] = Or<int32_t>::apply(tr[i], fr[i]);

    return StoreResult<Int32x4>(cx, args, orInt);
}

static bool
Float32x4Select(JSContext *cx, unsigned argc, Value *vp)
{
    CallArgs args = CallArgsFromVp(argc, vp);
    if (args.length() != 3 || !IsVectorObject<Int32x4>(args[0]) ||
        !IsVectorObject<Float32x4>(args[1]) || !IsVectorObject<Float32x4>(args[2]))
    {
        return ErrorBadArgs(cx);
    }

    int32_t *val = TypedObjectMemory<int32_t *>(args[0]);
    int32_t *tv = TypedObjectMemory<int32_t *>(args[1]);
    int32_t *fv = TypedObjectMemory<int32_t *>(args[2]);

    int32_t tr[Int32x4::lanes];
    for (unsigned i = 0; i < Int32x4::lanes; i++)
        tr[i] = And<int32_t>::apply(val[i], tv[i]);

    int32_t fr[Int32x4::lanes];
    for (unsigned i = 0; i < Int32x4::lanes; i++)
        fr[i] = And<int32_t>::apply(Not<int32_t>::apply(val[i]), fv[i]);

    int32_t orInt[Int32x4::lanes];
    for (unsigned i = 0; i < Int32x4::lanes; i++)
        orInt[i] = Or<int32_t>::apply(tr[i], fr[i]);

    float *result = reinterpret_cast<float *>(orInt);
    return StoreResult<Float32x4>(cx, args, result);
}

template<class VElem, unsigned NumElem>
static bool
TypedArrayDataPtrFromArgs(JSContext *cx, const CallArgs &args, VElem **data)
{
    if (!args[0].isObject())
        return ErrorBadArgs(cx);

    JSObject &argobj = args[0].toObject();
    if (!argobj.is<TypedArrayObject>())
        return ErrorBadArgs(cx);

    Rooted<TypedArrayObject*> typedArray(cx, &argobj.as<TypedArrayObject>());

    int32_t index;
    if (!ToInt32(cx, args[1], &index))
        return false;

    int32_t byteStart = index * typedArray->bytesPerElement();
    if (byteStart < 0 || (uint32_t(byteStart) + NumElem * sizeof(VElem)) > typedArray->byteLength())
    {
        JS_ReportErrorNumber(cx, js_GetErrorMessage, nullptr, JSMSG_BAD_INDEX);
        return false;
    }

    *data = reinterpret_cast<VElem*>(static_cast<char*>(typedArray->viewData()) + byteStart);
    return true;
}

template<class V, unsigned NumElem>
static bool
Load(JSContext *cx, unsigned argc, Value *vp)
{
    typedef typename V::Elem Elem;

    CallArgs args = CallArgsFromVp(argc, vp);
    if (args.length() != 2)
        return ErrorBadArgs(cx);

    Elem *typedArrayData = nullptr;
    if (!TypedArrayDataPtrFromArgs<Elem, NumElem>(cx, args, &typedArrayData))
        return false;

    Rooted<TypeDescr*> typeDescr(cx, &V::GetTypeDescr(*cx->global()));
    MOZ_ASSERT(typeDescr);
    Rooted<TypedObject *> result(cx, OutlineTypedObject::createZeroed(cx, typeDescr, 0));
    if (!result)
        return false;

    Elem *dest = reinterpret_cast<Elem*>(result->typedMem());
    for (unsigned i = 0; i < NumElem; i++)
        dest[i] = typedArrayData[i];

    args.rval().setObject(*result);
    return true;
}

template<class V, unsigned NumElem>
static bool
Store(JSContext *cx, unsigned argc, Value *vp)
{
    typedef typename V::Elem Elem;

    CallArgs args = CallArgsFromVp(argc, vp);
    if (args.length() != 3)
        return ErrorBadArgs(cx);

    Elem *typedArrayData = nullptr;
    if (!TypedArrayDataPtrFromArgs<Elem, NumElem>(cx, args, &typedArrayData))
        return false;

    if (!IsVectorObject<V>(args[2]))
        return ErrorBadArgs(cx);

    Elem *src = TypedObjectMemory<Elem*>(args[2]);
    for (unsigned i = 0; i < NumElem; i++)
        typedArrayData[i] = src[i];

    args.rval().setObject(args[2].toObject());
    return true;
}

#define DEFINE_SIMD_FLOAT32X4_FUNCTION(Name, Func, Operands, Flags) \
bool                                                                \
js::simd_float32x4_##Name(JSContext *cx, unsigned argc, Value *vp)  \
{                                                                   \
    return Func(cx, argc, vp);                                      \
}
FLOAT32X4_FUNCTION_LIST(DEFINE_SIMD_FLOAT32X4_FUNCTION)
#undef DEFINE_SIMD_FLOAT32x4_FUNCTION

#define DEFINE_SIMD_INT32X4_FUNCTION(Name, Func, Operands, Flags)   \
bool                                                                \
js::simd_int32x4_##Name(JSContext *cx, unsigned argc, Value *vp)    \
{                                                                   \
    return Func(cx, argc, vp);                                      \
}
INT32X4_FUNCTION_LIST(DEFINE_SIMD_INT32X4_FUNCTION)
#undef DEFINE_SIMD_INT32X4_FUNCTION

const JSFunctionSpec js::Float32x4Methods[] = {
#define SIMD_FLOAT32X4_FUNCTION_ITEM(Name, Func, Operands, Flags)   \
        JS_FN(#Name, js::simd_float32x4_##Name, Operands, Flags),
        FLOAT32X4_FUNCTION_LIST(SIMD_FLOAT32X4_FUNCTION_ITEM)
#undef SIMD_FLOAT32x4_FUNCTION_ITEM
        JS_FS_END
};

const JSFunctionSpec js::Int32x4Methods[] = {
#define SIMD_INT32X4_FUNCTION_ITEM(Name, Func, Operands, Flags)     \
        JS_FN(#Name, js::simd_int32x4_##Name, Operands, Flags),
        INT32X4_FUNCTION_LIST(SIMD_INT32X4_FUNCTION_ITEM)
#undef SIMD_INT32X4_FUNCTION_ITEM
        JS_FS_END
};
