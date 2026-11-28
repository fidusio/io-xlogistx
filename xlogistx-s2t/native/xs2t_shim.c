/*
 * xs2t shim: the stable C surface that the Java module io.xlogistx.s2t binds through FFM.
 *
 * Why it exists: whisper.h passes two large structs by value (whisper_context_params and
 * whisper_full_params), and both change between whisper.cpp releases. A Java-side copy of
 * those layouts breaks silently on a whisper upgrade. Everything exported here takes and
 * returns only pointers, ints and C strings, so the Java side never describes a whisper
 * struct. Upgrading whisper.cpp means rebuilding this DLL; the Java code does not change.
 *
 * Bump XS2T_ABI_VERSION whenever a function below changes its signature or meaning.
 * The Java loader refuses a DLL whose ABI version it does not know.
 */

#include "whisper.h"

#include <stddef.h>

#if defined(_WIN32)
#  define XS2T_API __declspec(dllexport)
#else
#  define XS2T_API __attribute__((visibility("default")))
#endif

#define XS2T_ABI_VERSION 1

/* Bit flags for xs2t_transcribe(). Mirrored in io.xlogistx.s2t.whisper.WhisperNative. */
#define XS2T_FLAG_SINGLE_SEGMENT 0x01   /* force the whole input into one segment   */
#define XS2T_FLAG_NO_CONTEXT     0x02   /* do not carry text over from the last call */
#define XS2T_FLAG_TRANSLATE      0x04   /* translate to English instead of transcribing */

/* Error codes returned by xs2t_transcribe() in addition to whisper_full()'s own. */
#define XS2T_ERR_BAD_ARGUMENT (-100)

static void xs2t_log_silent(enum ggml_log_level level, const char * text, void * user_data) {
    (void) level;
    (void) text;
    (void) user_data;
}

/* Version of this shim's function set. */
XS2T_API int xs2t_abi_version(void) {
    return XS2T_ABI_VERSION;
}

/* The whisper.cpp version this DLL was built from, e.g. "1.9.1". Static storage. */
XS2T_API const char * xs2t_whisper_version(void) {
    return whisper_version();
}

/* CPU features the build uses, e.g. "AVX = 1 | AVX2 = 1 | ...". Static storage. */
XS2T_API const char * xs2t_system_info(void) {
    return whisper_print_system_info();
}

/* enabled == 0 silences whisper's stderr logging; non-zero restores the default logger. */
XS2T_API void xs2t_set_log_enabled(int enabled) {
    whisper_log_set(enabled ? NULL : xs2t_log_silent, NULL);
}

/*
 * Loads a ggml model file. Returns NULL when the file is missing or not a model.
 * The returned context must be released with xs2t_close().
 * A context must not be used by two threads at once.
 */
XS2T_API struct whisper_context * xs2t_open(const char * model_path, int use_gpu) {
    if (model_path == NULL || model_path[0] == '\0') {
        return NULL;
    }
    struct whisper_context_params params = whisper_context_default_params();
    params.use_gpu = use_gpu != 0;
    return whisper_init_from_file_with_params(model_path, params);
}

XS2T_API void xs2t_close(struct whisper_context * ctx) {
    if (ctx != NULL) {
        whisper_free(ctx);
    }
}

/*
 * Runs speech recognition over samples: 16 kHz, mono, 32-bit float in [-1, 1].
 *
 *   n_threads       <= 0 keeps whisper's default
 *   language        e.g. "en"; NULL or "" keeps whisper's default
 *   initial_prompt  vocabulary hint; NULL or "" for none
 *   flags           XS2T_FLAG_* bits
 *
 * Returns 0 on success, XS2T_ERR_BAD_ARGUMENT, or whisper_full()'s non-zero error.
 * language and initial_prompt only need to stay valid for the duration of the call.
 * Read the result with xs2t_segment_count() and xs2t_segment_text().
 */
XS2T_API int xs2t_transcribe(struct whisper_context * ctx,
                             const float * samples,
                             int n_samples,
                             int n_threads,
                             const char * language,
                             const char * initial_prompt,
                             int flags) {
    if (ctx == NULL || samples == NULL || n_samples <= 0) {
        return XS2T_ERR_BAD_ARGUMENT;
    }

    struct whisper_full_params params = whisper_full_default_params(WHISPER_SAMPLING_GREEDY);

    if (n_threads > 0) {
        params.n_threads = n_threads;
    }
    params.print_special    = false;
    params.print_progress   = false;
    params.print_realtime   = false;
    params.print_timestamps = false;
    params.no_timestamps    = true;
    params.single_segment   = (flags & XS2T_FLAG_SINGLE_SEGMENT) != 0;
    params.no_context       = (flags & XS2T_FLAG_NO_CONTEXT) != 0;
    params.translate        = (flags & XS2T_FLAG_TRANSLATE) != 0;

    if (language != NULL && language[0] != '\0') {
        params.language = language;
    }
    if (initial_prompt != NULL && initial_prompt[0] != '\0') {
        params.initial_prompt = initial_prompt;
    }

    return whisper_full(ctx, params, samples, n_samples);
}

/* Number of text segments produced by the last xs2t_transcribe() on this context. */
XS2T_API int xs2t_segment_count(struct whisper_context * ctx) {
    return ctx != NULL ? whisper_full_n_segments(ctx) : 0;
}

/*
 * UTF-8 text of one segment, or NULL when index is out of range.
 * The pointer is owned by the context and is valid until the next xs2t_transcribe()
 * or xs2t_close() on it: copy the text before either.
 */
XS2T_API const char * xs2t_segment_text(struct whisper_context * ctx, int index) {
    if (ctx == NULL || index < 0 || index >= whisper_full_n_segments(ctx)) {
        return NULL;
    }
    return whisper_full_get_segment_text(ctx, index);
}
