#include <string.h>
#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <unistd.h>
#include "javahook.h"

#define LOG_TAG "dexload"
#define ALOGD(fmt, args...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)// 定义LOG类型
#define ALOGI(fmt, args...)  __android_log_print(ANDROID_LOG_INFO,LOG_TAG, fmt, ##args) // 定义LOG类型
#define ALOGW(fmt, args...)  __android_log_print(ANDROID_LOG_WARN,LOG_TAG, fmt, ##args) // 定义LOG类型
#define ALOGE(fmt, args...)  __android_log_print(ANDROID_LOG_ERROR,LOG_TAG, fmt, ##args) // 定义LOG类型
#define ALOGF(fmt, args...)  __android_log_print(ANDROID_LOG_FATAL,LOG_TAG, fmt, ##args) // 定义LOG类型

JNIEnv* g_env;
JavaVM* (*getJavaVM)();
JNIEnv* (*getJNIEnv)();
static void HookJavaHander(const u4* args, void* pResult, const Method* method, void* self);


//一些动态函数定义
typedef ClassObject* (*PFN_dvmFindArrayClass)(const char* descriptor, Object* loader);
typedef int (*PFN_dvmWriteBarrierArray)(ArrayObject const*, unsigned int, unsigned int);
typedef ClassObject* (*PFN_dvmFindPrimitiveClass)(char type);
typedef Object* (*PFN_dvmBoxPrimitive)(jvalue, ClassObject* returnType);
typedef bool (*PFN_dvmUnboxPrimitive)(Object* value, ClassObject* returnType,
    int* pResult);
typedef int* (*PFN_dvmThreadSelf)();
typedef Object* (*PFN_dvmDecodeIndirectRef)(int* self, jobject jobj);
typedef void (*PFN_dvmCallMethod)(int* self, const Method* method, Object* obj,
    int* pResult, ...);
typedef bool (*PFN_dvmCheckException)(int* self);
typedef ClassObject* (*PFN_dvmGetBoxedReturnType)(const Method* meth);
typedef bool (*PFN_dvmIsPrimitiveClass)(const ClassObject* clazz);

//自己实现一些dvm函数
#define ACC_STATIC 0x00000008       // field, method, ic
inline bool dvmIsStaticMethod(const Method* method) {
    return (method->accessFlags & ACC_STATIC) != 0;
}

inline s8 dvmGetArgLong(const u4* args, int elem)
{
    s8 val;
    memcpy(&val, &args[elem], sizeof(val));
    return val;
}

inline bool dvmIsPrimitiveClass(const ClassObject* clazz) {
    return clazz->primitiveType != 0/*prim_not*/;
}

//全局函数
PFN_dvmFindArrayClass pfndvmFindArrayClass = 0;
PFN_dvmWriteBarrierArray pfndvmWriteBarrierArray = 0;
PFN_dvmFindPrimitiveClass pfndvmFindPrimitiveClass = 0;
PFN_dvmBoxPrimitive pfndvmBoxPrimitive = 0;
PFN_dvmUnboxPrimitive pfndvmUnboxPrimitive = 0;
PFN_dvmThreadSelf pfndvmThreadSelf = 0;
PFN_dvmDecodeIndirectRef pfndvmDecodeIndirectRef = 0;
PFN_dvmCallMethod pfndvmCallMethod = 0;
PFN_dvmCheckException pfndvmCheckException = 0;
PFN_dvmGetBoxedReturnType pfndvmGetBoxedReturnType = 0;
PFN_dvmIsPrimitiveClass pfndvmIsPrimitiveClass = 0;

//功能：初始化一些全局函数
int InitFunction()
{
	void *handle;
	handle = dlopen("/system/lib/libdvm.so",RTLD_NOW);
	pfndvmFindArrayClass = dlsym(handle,"_Z17dvmFindArrayClassPKcP6Object");
	pfndvmWriteBarrierArray = dlsym(handle,"_Z20dvmWriteBarrierArrayPK11ArrayObjectjj");
	pfndvmFindPrimitiveClass = dlsym(handle,"_Z21dvmFindPrimitiveClassc");
	pfndvmBoxPrimitive = dlsym(handle,"_Z15dvmBoxPrimitive6JValueP11ClassObject");
    pfndvmUnboxPrimitive = dlsym(handle,"_Z17dvmUnboxPrimitiveP6ObjectP11ClassObjectP6JValue");
    pfndvmThreadSelf = dlsym(handle,"_Z13dvmThreadSelfv");
    pfndvmDecodeIndirectRef = dlsym(handle,"_Z20dvmDecodeIndirectRefP6ThreadP8_jobject");
    pfndvmCallMethod = dlsym(handle,"_Z13dvmCallMethodP6ThreadPK6MethodP6ObjectP6JValuez");
    pfndvmCheckException = dlsym(handle,"_Z17dvmCheckExceptionP6Thread");
    pfndvmGetBoxedReturnType = dlsym(handle,"_Z21dvmGetBoxedReturnTypePK6Method");
    pfndvmIsPrimitiveClass = dlsym(handle,"_Z19dvmIsPrimitiveClassPK11ClassObject");

    ALOGD("pfndvmFindArrayClass addr:0x%X",pfndvmFindArrayClass);
    ALOGD("pfndvmWriteBarrierArray addr:0x%X",pfndvmWriteBarrierArray);
    ALOGD("pfndvmFindPrimitiveClass addr:0x%X",pfndvmFindPrimitiveClass);
    ALOGD("pfndvmBoxPrimitive addr:0x%X",pfndvmBoxPrimitive);
    ALOGD("pfndvmUnboxPrimitive addr:0x%X",pfndvmUnboxPrimitive);
    ALOGD("pfndvmThreadSelf addr:0x%X",pfndvmThreadSelf);
    ALOGD("pfndvmDecodeIndirectRef addr:0x%X",pfndvmDecodeIndirectRef);
    ALOGD("pfndvmCallMethod addr:0x%X",pfndvmCallMethod);
    ALOGD("pfndvmCheckException addr:0x%X",pfndvmCheckException);
    ALOGD("pfndvmGetBoxedReturnType addr:0x%X",pfndvmGetBoxedReturnType);
    ALOGD("pfndvmIsPrimitiveClass addr:0x%X",pfndvmIsPrimitiveClass);
    dlclose(handle);
    return 1;
}

//功能：调用dexPath文件中的className类的methodName方法。
//dexPath: dex/jar/apk 文件路径
//dexOptDir: 优化目录, 这个目录的owner必须是要被注入进程的user，否则dex优化会失败
//className: 目标类名，如“com.hook.Test”
//methodName: 目标方法名，如"main", 在Java代码里必须定义为public static void main(String[] args);
//argc，传给目标方法的参数个数
//argv，传给目标方法的参数
int invoke_dex_method(const char* dexPath, const char* dexOptDir, const char* className, const char* methodName, int argc, char *argv[]) {
	void *handle;
	JavaVM* g_JavaVm;
	JNIEnv* env;
	
	jclass stringClass, classLoaderClass, dexClassLoaderClass, targetClass;
    jmethodID getSystemClassLoaderMethod, dexClassLoaderContructor, loadClassMethod, targetMethod;
    jobject systemClassLoaderObject, dexClassLoaderObject;
    jstring dexPathString, dexOptDirString, classNameString, tmpString;    
    jobjectArray stringArray;
	
	int i;
	
	ALOGD("Invoke dex E");
	handle = dlopen("/system/lib/libandroid_runtime.so", RTLD_NOW);
	getJNIEnv = dlsym(handle, "_ZN7android14AndroidRuntime9getJNIEnvEv");
	
	// static JavaVM* getJavaVM() { return mJavaVM; }
	g_JavaVm = dlsym(handle, "_ZN7android14AndroidRuntime7mJavaVME");

    ALOGD("getJNIEnv addr:0x%X",getJNIEnv);
    ALOGD("g_JavaVm addr:0x%X",g_JavaVm);

    env = getJNIEnv();
    ALOGD("env addr:0x%X",env);
    /* Get SystemClasLoader */
    stringClass = (*env)->FindClass(env,"java/lang/String");
    classLoaderClass = (*env)->FindClass(env,"java/lang/ClassLoader");
    dexClassLoaderClass = (*env)->FindClass(env,"dalvik/system/DexClassLoader");
    getSystemClassLoaderMethod = (*env)->GetStaticMethodID(env,classLoaderClass, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
    systemClassLoaderObject = (*env)->CallStaticObjectMethod(env,classLoaderClass, getSystemClassLoaderMethod);
    /* Create DexClassLoader */
    dexClassLoaderContructor = (*env)->GetMethodID(env,dexClassLoaderClass, "<init>", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V");
    dexPathString = (*env)->NewStringUTF(env,dexPath);
    dexOptDirString = (*env)->NewStringUTF(env,dexOptDir);
    dexClassLoaderObject = (*env)->NewObject(env,dexClassLoaderClass, dexClassLoaderContructor, dexPathString, dexOptDirString, NULL, systemClassLoaderObject);

    ALOGD("call dexClassLoaderObject!!!!!!!dexClassLoaderObject :0x%X",dexClassLoaderObject);
    ALOGD("dexClassLoaderClass:0x%X",dexClassLoaderClass);
    /* Use DexClassLoader to load target class */
    loadClassMethod = (*env)->GetMethodID(env, dexClassLoaderClass,"findClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    ALOGD("call findClassMethod");
    if (NULL == loadClassMethod)
    {
        loadClassMethod = (*env)->GetMethodID(env,dexClassLoaderClass, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    }
    ALOGD("call loadClassMethod");
    classNameString = (*env)->NewStringUTF(env,className);

    ALOGD("fuck whats!!!!!!!!!!! %s",className);
    targetClass = (jclass)(*env)->CallObjectMethod(env,dexClassLoaderObject, loadClassMethod, classNameString);
    if (!targetClass) {
        ALOGE("Failed to load target class %s", className);
        return -1;
    }
    /* Invoke target method */
    targetMethod = (*env)->GetStaticMethodID(env,targetClass, methodName, "([Ljava/lang/String;)V");
    if (!targetMethod) {
        ALOGE("Failed to load target method %s", methodName);
        return -1;
    }
    ALOGD("call targetMethod");
    stringArray = (*env)->NewObjectArray(env,argc, stringClass, NULL);
    for (i = 0; i < argc; i++) {
        tmpString = (*env)->NewStringUTF(env,argv[i]);
        (*env)->SetObjectArrayElement(env,stringArray, i, tmpString);
    }
    (*env)->CallStaticVoidMethod(env,targetClass, targetMethod, stringArray);
    ALOGD("Invoke dex X"); 
	g_env = env;
    return 0;
}


bool IsHooked(Method* method)
{
	if(method->nativeFunc == &HookJavaHander)
		return TRUE;
	else
		return FALSE;
}

u4 arrayContentsOffset = 8;
static inline void SetObjectArrayElement(const ArrayObject* obj, int index, Object* val) {
    uintptr_t arrayContents = (uintptr_t)obj + arrayContentsOffset;
    ((Object **)arrayContents)[index] = val;
    pfndvmWriteBarrierArray(obj, index, index + 1);
}

//todo
ClassObject* objectArrayClass = NULL;
static void HookJavaHander(const u4* args, void* pResult, const Method* method, void* self) {
    JNIEnv* env;
	jclass objClass;
	ArrayObject* argsArray;
	
	if (!IsHooked(method)) {
        ALOGD("could not find original method - how did you even get here?");
        return;
    }
	env = getJNIEnv();
	
    PHOOKINFO hookInfo = (PHOOKINFO) method->insns;
    Method* original = (Method*) hookInfo;
    Object* originalReflected = hookInfo->origMethodIndex;
    //Object* additionalInfo = hookInfo->additionalInfo;
  
    // convert/box arguments
    const char* desc = &method->shorty[1]; // [0] is the return type.
    Object* thisObject = NULL;
    size_t srcIndex = 0;
    size_t dstIndex = 0;
    
    // for non-static methods determine the "this" pointer
    if (!dvmIsStaticMethod(original)) {
        thisObject = (Object*) args[0];
        srcIndex++;
    }
	
	objectArrayClass = pfndvmFindArrayClass("[Ljava/lang/Object;", NULL);
	argsArray = dvmAllocArrayByClass(objectArrayClass, strlen(method->shorty) - 1+1, 0);
    if (argsArray == NULL) {
        return;
    }
    
    while (*desc != '\0') {
        char descChar = *(desc++);
        jvalue value;
        Object* obj;

        switch (descChar) {
        case 'Z':
        case 'C':
        case 'F':
        case 'B':
        case 'S':
        case 'I':
            value.i = args[srcIndex++];
            obj = (Object*) pfndvmBoxPrimitive(value, pfndvmFindPrimitiveClass(descChar));
            dvmReleaseTrackedAlloc(obj, self);
            break;
        case 'D':
        case 'J':
            value.j = dvmGetArgLong(args, srcIndex);
            srcIndex += 2;
            obj = (Object*) pfndvmBoxPrimitive(value, pfndvmFindPrimitiveClass(descChar));
            dvmReleaseTrackedAlloc(obj, self);
            break;
        case '[':
        case 'L':
            obj  = (Object*) args[srcIndex++];
            break;
        default:
            ALOGE("Unknown method signature description character: %c\n", descChar);
            obj = NULL;
            srcIndex++;
        }
        SetObjectArrayElement(argsArray, dstIndex++, obj);
    }
    //call the Hooked function
	
	SetObjectArrayElement(argsArray, dstIndex, original); 	//最后一个参数是原函数
    jvalue result;
	Method* NewMethod = pfndvmDecodeIndirectRef(pfndvmThreadSelf(),hookInfo->newMethodIndex);
    pfndvmCallMethod(self, NewMethod, NULL, &result,argsArray);
        
    dvmReleaseTrackedAlloc(argsArray, self);

    // exceptions are thrown to the caller
    if (pfndvmCheckException(self)) {
        return;
    }

    // return result with proper type
    ClassObject* returnType = pfndvmGetBoxedReturnType(method);
    if (returnType->primitiveType == PRIM_VOID) {
        // ignored
    } else if (result.l == NULL) {
        if (dvmIsPrimitiveClass(returnType)) {
            dvmThrowNullPointerException("null result when primitive expected");
        }
        //pResult->l = NULL;
    } else {
        if (!pfndvmUnboxPrimitive(result.l, returnType, pResult)) {
            //dvmThrowClassCastException(result.l->clazz, returnType);
        }
    }
}


static int HookJavaMethod(JNIEnv* env, jclass clazz, jobject reflectedMethodIndirect,
            jobject declaredClassIndirect, jobject newMethod)
{
	 if (declaredClassIndirect == NULL || reflectedMethodIndirect == NULL) {
        ALOGD("method and declaredClass must not be null");
        return -1;
    }
    
    // Find the internal representation of the method
    ClassObject* declaredClass = (ClassObject*) dvmDecodeIndirectRef(dvmThreadSelf(), declaredClassIndirect);
    Method* method = pfndvmDecodeIndirectRef(dvmThreadSelf(), reflectedMethodIndirect);
    if (method == NULL) {
        ALOGD("could not get internal representation for method");
        return -1;
    }
    
    if (IsHooked(method)) {
        // already hooked
        return -1;
    }
    
    // Save a copy of the original method and other hook info
    PHOOKINFO hookInfo = (PHOOKINFO) calloc(1, sizeof(HOOKINFO));
    memcpy(hookInfo, method, sizeof(Method));
    hookInfo->origMethodIndex = reflectedMethodIndirect;
	hookInfo->newMethodIndex = newMethod;

    // Replace method with our own code
    SET_METHOD_FLAG(method, ACC_NATIVE);
    method->nativeFunc = &HookJavaHander;
    method->insns = (const u2*) hookInfo;		//方便快速查找，不用查表
    method->registersSize = method->insSize;
    method->outsSize = 0;

    /*if (PTR_gDvmJit != NULL) {
        // reset JIT cache
        MEMBER_VAL(PTR_gDvmJit, DvmJitGlobals, codeCacheFull) = true;
    }*/
	return 0;
}
	
static JNINativeMethod gMethods[] = {
	{ "HookMethod", "()Ljava/lang/String;", (void*)HookJavaMethod },//绑定
};

static int registerNativeMethods(JNIEnv* env, const char* className,
        JNINativeMethod* gMethods, int numMethods)
{
	jclass clazz;
	clazz = (*env)->FindClass(env, className);
	if (clazz == NULL) {
		return JNI_FALSE;
	}
	if ((*env)->RegisterNatives(env, clazz, gMethods, numMethods) < 0) {
		return JNI_FALSE;
	}

	return JNI_TRUE;
}

#define JNIREG_CLASS "app/hookclass"

static int RegisterJniFunction(JNIEnv* env)
{
	if (!registerNativeMethods(env, JNIREG_CLASS, gMethods,sizeof(gMethods) / sizeof(gMethods[0])))
		return JNI_FALSE;
	return 0;
}

static int firstCall = 0;

void __attribute__((constructor)) start(const char* dexPath)
{
    /*
	if(invoke_dex_method(dexPath))
		return 1;
	RegisterJniFunction(g_env);
    */
    if (firstCall != 0)
    {
        return;
    }
    firstCall++;
    ALOGD("just test so");
    InitFunction();
    if(invoke_dex_method("/data/local/tmp/remotejar.jar","/data/data/目标进程名/app_dexfile","com/dexload/test/test","main",1,"test"))
        return 1;
}

