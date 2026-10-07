#include <jni.h>
#include <appdome.hpp>
#include <logcat.hpp>

/**
 * Entry point for appdome.
 */
void Java_qwerty_asdfgh_zxcvbn_lkjhgf(JNIEnv *env, jclass _)
{
    (void)_;
    std::string blobs_config = assets::get_by_uuid(BLOBS_CONFIG_NAME);
    if (blobs_config.empty())
    {
        log_E("Failed to load blobs config.");
        return;
    }

    log_D("got %zu bytes", blobs_config.size());

    assets::populate_hash_map(blobs_config);

    auto natives = natives::get_native_methods_to_register();
    if (natives.empty())
    {
        log_E("No native methods resolved to register.");
        return;
    }

    auto natives_arr = natives::map_to_jni_arr(natives);

    auto clazz_name = natives.at(0).clazz; // all natives should be in the same class
    jclass clazz = env->FindClass(clazz_name.c_str());
    if (clazz == nullptr)
    {
        log_E("Failed to find class for native methods: %s", clazz_name.c_str());
        return;
    }

    env->RegisterNatives(clazz, natives_arr, natives.size());
    log_I("Registered %zu native methods for class: %s", natives.size(), clazz_name.c_str());
}

extern "C"
{
    JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved)
    {
        (void)reserved;

        // here we register the entry point.
        JNIEnv *env;
        if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK)
        {
            return JNI_ERR;
        }

        auto appdome_init_class = env->FindClass("qwerty/asdfgh/zxcvbn");
        if (env->RegisterNatives(appdome_init_class, (JNINativeMethod[]){{"lkjhgf", "()V", (void *)Java_qwerty_asdfgh_zxcvbn_lkjhgf}}, 1) < 0)
        {
            return JNI_ERR;
        }

        return JNI_VERSION_1_6;
    }
}