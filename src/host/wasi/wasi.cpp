/*
 * Copyright (C) 2019 Intel Corporation.
 * Copyright (C) 2021-2023 the DTVM authors.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "host/wasi/wasi.h"

#include <climits>
#include <fcntl.h>
#include <string_view>

#include "sandboxed-system-primitives/include/wasmtime_ssp.h"
#include "sandboxed-system-primitives/src/posix.h"

#include "common/errors.h"
#include "runtime/instance.h"

namespace zen::host {

typedef __wasi_errno_t wasi_errno_t;
typedef __wasi_fd_t wasi_fd_t;
typedef __wasi_clockid_t wasi_clockid_t;
typedef __wasi_timestamp_t wasi_timestamp_t;
typedef __wasi_prestat_t wasi_prestat_t;
typedef __wasi_iovec_t wasi_iovec_t;
typedef __wasi_ciovec_t wasi_ciovec_t;
typedef __wasi_filetype_t wasi_filetype_t;
typedef __wasi_filesize_t wasi_filesize_t;
typedef __wasi_filedelta_t wasi_filedelta_t;
typedef __wasi_whence_t wasi_whence_t;
typedef __wasi_fdstat_t wasi_fdstat_t;
typedef __wasi_fdflags_t wasi_fdflags_t;
typedef __wasi_rights_t wasi_rights_t;
typedef __wasi_advice_t wasi_advice_t;
typedef __wasi_lookupflags_t wasi_lookupflags_t;
typedef __wasi_oflags_t wasi_oflags_t;
typedef __wasi_dircookie_t wasi_dircookie_t;
typedef __wasi_filestat_t wasi_filestat_t;
typedef __wasi_fstflags_t wasi_fstflags_t;
typedef __wasi_subscription_t wasi_subscription_t;
typedef __wasi_event_t wasi_event_t;
typedef __wasi_exitcode_t wasi_exitcode_t;
typedef __wasi_signal_t wasi_signal_t;
typedef __wasi_riflags_t wasi_riflags_t;
typedef __wasi_roflags_t wasi_roflags_t;
typedef __wasi_siflags_t wasi_siflags_t;
typedef __wasi_sdflags_t wasi_sdflags_t;
typedef __wasi_preopentype_t wasi_preopentype_t;

typedef struct wasi_prestat_app {
  wasi_preopentype_t pr_type;
  uint32_t pr_name_len;
} wasi_prestat_app_t;

typedef struct iovec_app {
  uint32_t buf_offset;
  uint32_t buf_len;
} iovec_app_t;

typedef WASIContext *wasi_ctx_t;

#define runtime_malloc(size) ((void *)vmenv->allocMem(size))
#define runtime_free(ptr) (vmenv->freeMem(ptr))

#define getNativeCtxFromInstance(instance) (instance->getWASIContext())

// ======================== Reserved Ctx related Functions
// ========================
static void *vnmi_init_ctx(VNMIEnv *vmenv, const char *dir_list[],
                           uint32_t dir_count, const char *env_list[],
                           uint32_t env_count, char *env_buf,
                           uint32_t env_buf_size, char *argv_list[],
                           uint32_t argc, char *argv_buf,
                           uint32_t argv_buf_size) {
  fd_table *curfds = nullptr;
  fd_prestats *prestats = nullptr;
  argv_environ_values *argv_environ = nullptr;
  __wasi_fd_t wasm_fd = 3;

  if (!vmenv) {
    return nullptr;
  }

  auto wasi_ctx =
      static_cast<WASIContext *>(vmenv->allocMem(sizeof(WASIContext)));
  if (!wasi_ctx) {
    return nullptr;
  }

  curfds = static_cast<fd_table *>(vmenv->allocMem(sizeof(fd_table)));
  if (!curfds) {
    goto fail;
  }

  prestats = static_cast<fd_prestats *>(vmenv->allocMem(sizeof(fd_prestats)));
  if (!prestats) {
    goto fail;
  }

  argv_environ = static_cast<argv_environ_values *>(
      vmenv->allocMem(sizeof(argv_environ_values)));
  if (!argv_environ) {
    goto fail;
  }

  if (!fd_table_init(curfds)) {
    goto fail;
  }
  if (!fd_prestats_init(prestats)) {
    goto fail;
  }
  if (!argv_environ_init(argv_environ, argv_buf, argv_buf_size, argv_list, argc,
                         env_buf, env_buf_size, const_cast<char **>(env_list),
                         env_count)) {
    goto fail;
  }
  if (!fd_table_insert_existing(curfds, 0, 0) ||
      !fd_table_insert_existing(curfds, 1, 1) ||
      !fd_table_insert_existing(curfds, 2, 2)) {
    goto fail;
  }

  char resolved_path[PATH_MAX];
  for (uint32_t i = 0; i < dir_count; i++, wasm_fd++) {
    char *path = realpath(dir_list[i], resolved_path);
    if (!path) {
      goto fail;
    }
    int raw_fd = open(path, O_DIRECTORY | O_RDONLY, 0);
    if (raw_fd == -1) {
      goto fail;
    }
    if (!fd_table_insert_existing(curfds, wasm_fd, raw_fd)) {
      goto fail;
    }
    if (!fd_prestats_insert(prestats, dir_list[i], wasm_fd)) {
      goto fail;
    }
  }

  wasi_ctx->curfds = curfds;
  wasi_ctx->prestats = prestats;
  wasi_ctx->argv_environ = argv_environ;
  wasi_ctx->argv_buf = argv_buf;
  wasi_ctx->argv_list = argv_list;
  wasi_ctx->env_buf = env_buf;
  wasi_ctx->env_list = const_cast<char **>(env_list);
  wasi_ctx->vnmi_env = vmenv;

  return wasi_ctx;

fail:
  if (argv_environ)
    argv_environ_destroy(argv_environ);
  if (prestats)
    fd_prestats_destroy(prestats);
  if (curfds)
    fd_table_destroy(curfds);
  if (curfds)
    vmenv->freeMem(curfds);
  if (prestats)
    vmenv->freeMem(prestats);
  if (argv_environ)
    vmenv->freeMem(argv_environ);
  if (wasi_ctx)
    vmenv->freeMem(wasi_ctx);
  return nullptr;
}

static void vnmi_destroy_ctx(VNMIEnv *vmenv, void *ctx) {
  WASIContext *wasi_ctx = reinterpret_cast<WASIContext *>(ctx);
  if (!vmenv || !ctx) {
    return;
  }

  if (wasi_ctx->curfds) {
    fd_table_destroy(wasi_ctx->curfds);
    vmenv->freeMem(wasi_ctx->curfds);
  }
  if (wasi_ctx->prestats) {
    fd_prestats_destroy(wasi_ctx->prestats);
    vmenv->freeMem(wasi_ctx->prestats);
  }
  if (wasi_ctx->argv_environ) {
    argv_environ_destroy(wasi_ctx->argv_environ);
    vmenv->freeMem(wasi_ctx->argv_environ);
  }

  vmenv->freeMem(ctx);
}

// ======================== [Begin] WASI Functions ========================
static inline struct fd_table *wasi_ctx_get_curfds(Instance *instance,
                                                   wasi_ctx_t wasi_ctx) {
  if (!wasi_ctx)
    return nullptr;
  return wasi_ctx->curfds;
}

static inline struct argv_environ_values *
wasi_ctx_get_argv_environ(Instance *instance, wasi_ctx_t wasi_ctx) {
  if (!wasi_ctx)
    return nullptr;
  return wasi_ctx->argv_environ;
}

static inline struct fd_prestats *wasi_ctx_get_prestats(Instance *instance,
                                                        wasi_ctx_t wasi_ctx) {
  if (!wasi_ctx)
    return nullptr;
  return wasi_ctx->prestats;
}

static wasi_errno_t wasi_args_get(Instance *instance, uint32_t *argv_offsets,
                                  char *argv_buf) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);

  struct argv_environ_values *argv_environ =
      wasi_ctx_get_argv_environ(instance, wasi_ctx);
  size_t argc, argv_buf_size, i;
  char **argv;
  uint64_t total_size;
  wasi_errno_t err;

  if (!wasi_ctx)
    return (wasi_errno_t)-1;
  VNMIEnv *vmenv = wasi_ctx->vnmi_env;

  err = wasmtime_ssp_args_sizes_get(argv_environ, &argc, &argv_buf_size);
  if (err)
    return err;

  total_size = sizeof(int32_t) * ((uint64_t)argc + 1);
  if (total_size >= UINT32_MAX ||
      !VALIDATE_APP_ADDR((uint32_t)(intptr_t)argv_offsets,
                         (uint32_t)total_size) ||
      argv_buf_size >= UINT32_MAX ||
      !VALIDATE_APP_ADDR((uint32_t)(intptr_t)argv_buf, (uint32_t)argv_buf_size))
    return (wasi_errno_t)-1;

  total_size = sizeof(char *) * ((uint64_t)argc + 1);
  if (total_size >= UINT32_MAX ||
      !(argv = (char **)runtime_malloc((uint32_t)total_size)))
    return (wasi_errno_t)-1;

  char *native_argv_buf =
      (char *)ADDR_APP_TO_NATIVE((uint32_t)(intptr_t)argv_buf);

  err = wasmtime_ssp_args_get(argv_environ, argv, native_argv_buf);
  if (err) {
    runtime_free(argv);
    return err;
  }

  uint32_t *native_argv_offsets =
      (uint32_t *)ADDR_APP_TO_NATIVE((uint32_t)(intptr_t)argv_offsets);

  for (i = 0; i < argc; i++)
    native_argv_offsets[i] = ADDR_NATIVE_TO_APP(argv[i]);

  runtime_free(argv);
  return 0;
}

static wasi_errno_t wasi_args_sizes_get(Instance *instance, uint32_t *argc_app,
                                        uint32_t *argv_buf_size_app) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct argv_environ_values *argv_environ;
  size_t argc, argv_buf_size;
  wasi_errno_t err;

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  if (!VALIDATE_APP_ADDR((uint32_t)(intptr_t)argc_app, sizeof(uint32_t)) ||
      !VALIDATE_APP_ADDR((uint32_t)(intptr_t)argv_buf_size_app,
                         sizeof(uint32_t)))
    return (wasi_errno_t)-1;

  argv_environ = wasi_ctx->argv_environ;

  err = wasmtime_ssp_args_sizes_get(argv_environ, &argc, &argv_buf_size);
  if (err)
    return err;

  uint32_t *native_argc_app =
      (uint32_t *)ADDR_APP_TO_NATIVE((uint32_t)(intptr_t)argc_app);
  uint32_t *native_argv_buf_size_app =
      (uint32_t *)ADDR_APP_TO_NATIVE((uint32_t)(intptr_t)argv_buf_size_app);
  *native_argc_app = (uint32_t)argc;
  *native_argv_buf_size_app = (uint32_t)argv_buf_size;
  return 0;
}

static wasi_errno_t
wasi_clock_res_get(Instance *instance,
                   wasi_clockid_t clock_id, /* uint32_t clock_id */
                   wasi_timestamp_t *resolution /* uint64_t *resolution */) {
  if (!VALIDATE_APP_ADDR((uint32_t)(intptr_t)resolution,
                         sizeof(wasi_timestamp_t)))
    return (wasi_errno_t)-1;

  wasi_timestamp_t *native_resolution =
      (wasi_timestamp_t *)ADDR_APP_TO_NATIVE((uint32_t)(intptr_t)resolution);

  return wasmtime_ssp_clock_res_get(clock_id, native_resolution);
}

static wasi_errno_t
wasi_clock_time_get(Instance *instance,
                    wasi_clockid_t clock_id,    /* uint32_t clock_id */
                    wasi_timestamp_t precision, /* uint64_t precision */
                    wasi_timestamp_t *time /* uint64_t *time */) {
  if (!VALIDATE_APP_ADDR((uint32_t)(intptr_t)time, sizeof(wasi_timestamp_t)))
    return (wasi_errno_t)-1;

  wasi_timestamp_t *native_time =
      (wasi_timestamp_t *)ADDR_APP_TO_NATIVE((uint32_t)(intptr_t)time);

  return wasmtime_ssp_clock_time_get(clock_id, precision, native_time);
}

static wasi_errno_t wasi_environ_get(Instance *instance,
                                     uint32_t *environ_offsets,
                                     char *environ_buf) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);

  struct argv_environ_values *argv_environ =
      wasi_ctx_get_argv_environ(instance, wasi_ctx);
  size_t environ_count, environ_buf_size, i;
  uint64_t total_size;
  char **environs;
  wasi_errno_t err;

  if (!wasi_ctx)
    return (wasi_errno_t)-1;
  VNMIEnv *vmenv = wasi_ctx->vnmi_env;

  err = wasmtime_ssp_environ_sizes_get(argv_environ, &environ_count,
                                       &environ_buf_size);
  if (err)
    return err;

  total_size = sizeof(int32_t) * ((uint64_t)environ_count + 1);
  if (total_size >= UINT32_MAX ||
      !VALIDATE_APP_ADDR((uint32_t)(intptr_t)environ_offsets,
                         (uint32_t)total_size) ||
      environ_buf_size >= UINT32_MAX ||
      !VALIDATE_APP_ADDR((uint32_t)(intptr_t)environ_buf,
                         (uint32_t)environ_buf_size))
    return (wasi_errno_t)-1;

  total_size = sizeof(char *) * (((uint64_t)environ_count + 1));

  if (total_size >= UINT32_MAX ||
      !(environs = (char **)runtime_malloc((uint32_t)total_size)))
    return (wasi_errno_t)-1;

  char *native_environ_buf =
      (char *)ADDR_APP_TO_NATIVE((uint32_t)(intptr_t)environ_buf);
  err = wasmtime_ssp_environ_get(argv_environ, environs, native_environ_buf);
  if (err) {
    runtime_free(environs);
    return err;
  }

  uint32_t *native_environ_offsets =
      (uint32_t *)ADDR_APP_TO_NATIVE((uint32_t)(intptr_t)environ_offsets);

  for (i = 0; i < environ_count; i++)
    native_environ_offsets[i] = ADDR_NATIVE_TO_APP(environs[i]);

  runtime_free(environs);
  return 0;
}

static wasi_errno_t wasi_environ_sizes_get(Instance *instance,
                                           uint32_t *environ_count_app,
                                           uint32_t *environ_buf_size_app) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct argv_environ_values *argv_environ =
      wasi_ctx_get_argv_environ(instance, wasi_ctx);
  size_t environ_count, environ_buf_size;
  wasi_errno_t err;

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  if (!VALIDATE_APP_ADDR((uint32_t)(intptr_t)environ_count_app,
                         sizeof(uint32_t)) ||
      !VALIDATE_APP_ADDR((uint32_t)(intptr_t)environ_buf_size_app,
                         sizeof(uint32_t)))
    return (wasi_errno_t)-1;

  err = wasmtime_ssp_environ_sizes_get(argv_environ, &environ_count,
                                       &environ_buf_size);
  if (err)
    return err;

  uint32_t *native_environ_count_app =
      (uint32_t *)ADDR_APP_TO_NATIVE((uint32_t)(intptr_t)environ_count_app);
  uint32_t *native_environ_buf_size_app =
      (uint32_t *)ADDR_APP_TO_NATIVE((uint32_t)(intptr_t)environ_buf_size_app);

  *native_environ_count_app = (uint32_t)environ_count;
  *native_environ_buf_size_app = (uint32_t)environ_buf_size;

  return 0;
}

static wasi_errno_t wasi_fd_prestat_get(Instance *instance, wasi_fd_t fd,
                                        wasi_prestat_app_t *prestat_app) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct fd_prestats *prestats = wasi_ctx_get_prestats(instance, wasi_ctx);
  wasi_prestat_t prestat;
  wasi_errno_t err;

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  if (!VALIDATE_APP_ADDR((uint32_t)(intptr_t)prestat_app,
                         sizeof(wasi_prestat_app_t)))
    return (wasi_errno_t)-1;

  err = wasmtime_ssp_fd_prestat_get(prestats, fd, &prestat);
  if (err)
    return err;

  wasi_prestat_app_t *native_prestat_app =
      (wasi_prestat_app_t *)ADDR_APP_TO_NATIVE((uint32_t)(intptr_t)prestat_app);

  native_prestat_app->pr_type = prestat.pr_type;
  native_prestat_app->pr_name_len = (uint32_t)prestat.u.dir.pr_name_len;
  return 0;
}

static wasi_errno_t wasi_fd_prestat_dir_name(Instance *instance, wasi_fd_t fd,
                                             char *path, uint32_t path_len) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct fd_prestats *prestats = wasi_ctx_get_prestats(instance, wasi_ctx);

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  if (!VALIDATE_APP_ADDR((uint32_t)(intptr_t)path, path_len))
    return (wasi_errno_t)-1;

  char *native_path = (char *)ADDR_APP_TO_NATIVE((uint32_t)(intptr_t)path);

  return wasmtime_ssp_fd_prestat_dir_name(prestats, fd, native_path, path_len);
}

static wasi_errno_t wasi_fd_close(Instance *instance, wasi_fd_t fd) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);
  struct fd_prestats *prestats = wasi_ctx_get_prestats(instance, wasi_ctx);

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  return wasmtime_ssp_fd_close(curfds, prestats, fd);
}

static wasi_errno_t wasi_fd_datasync(Instance *instance, wasi_fd_t fd) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  return wasmtime_ssp_fd_datasync(curfds, fd);
}

static wasi_errno_t wasi_fd_pread(Instance *instance, wasi_fd_t fd,
                                  iovec_app_t *iovec_app, uint32_t iovs_len,
                                  wasi_filesize_t offset, uint32_t *nread_app) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);

  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);
  wasi_iovec_t *iovec, *iovec_begin;
  uint64_t total_size;
  size_t nread;
  uint32_t i;
  wasi_errno_t err;

  if (!wasi_ctx)
    return (wasi_errno_t)-1;
  VNMIEnv *vmenv = wasi_ctx->vnmi_env;

  total_size = sizeof(iovec_app_t) * (uint64_t)iovs_len;
  if (!VALIDATE_APP_ADDR((uint32_t)(intptr_t)nread_app,
                         (uint32_t)sizeof(uint32_t)) ||
      total_size >= UINT32_MAX ||
      !VALIDATE_APP_ADDR((uint32_t)(intptr_t)iovec_app, (uint32_t)total_size))
    return (wasi_errno_t)-1;

  total_size = sizeof(wasi_iovec_t) * (uint64_t)iovs_len;
  if (total_size >= UINT32_MAX ||
      !(iovec_begin = (wasi_iovec_t *)runtime_malloc((uint32_t)total_size)))
    return (wasi_errno_t)-1;

  iovec = iovec_begin;

  iovec_app_t *native_iovec_app =
      (iovec_app_t *)ADDR_APP_TO_NATIVE((uint32_t)(intptr_t)iovec_app);

  for (i = 0; i < iovs_len; i++, native_iovec_app++, iovec++) {
    if (!VALIDATE_APP_ADDR(native_iovec_app->buf_offset,
                           native_iovec_app->buf_len)) {
      err = (wasi_errno_t)-1;
      runtime_free(iovec_begin);
      return err;
    }
    iovec->buf = (void *)ADDR_APP_TO_NATIVE(native_iovec_app->buf_offset);
    iovec->buf_len = native_iovec_app->buf_len;
  }

  err =
      wasmtime_ssp_fd_pread(curfds, fd, iovec_begin, iovs_len, offset, &nread);
  if (err) {
    runtime_free(iovec_begin);
    return err;
  }

  uint32_t *native_nread_app =
      (uint32_t *)ADDR_APP_TO_NATIVE((uint32_t)(intptr_t)nread_app);

  *native_nread_app = (uint32_t)nread;

  /* success */
  err = 0;

  runtime_free(iovec_begin);
  return err;
}

static wasi_errno_t wasi_fd_pwrite(Instance *instance, wasi_fd_t fd,
                                   const iovec_app_t *iovec_app,
                                   uint32_t iovs_len, wasi_filesize_t offset,
                                   uint32_t *nwritten_app) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);

  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);
  wasi_ciovec_t *ciovec, *ciovec_begin;
  uint64_t total_size;
  size_t nwritten;
  uint32_t i;
  wasi_errno_t err;

  if (!wasi_ctx)
    return (wasi_errno_t)-1;
  VNMIEnv *vmenv = wasi_ctx->vnmi_env;

  total_size = sizeof(iovec_app_t) * (uint64_t)iovs_len;
  if (!VALIDATE_APP_ADDR((uint32_t)(intptr_t)nwritten_app,
                         (uint32_t)sizeof(uint32_t)) ||
      total_size >= UINT32_MAX ||
      !VALIDATE_APP_ADDR((uint32_t)(intptr_t)iovec_app, (uint32_t)total_size))
    return (wasi_errno_t)-1;

  total_size = sizeof(wasi_ciovec_t) * (uint64_t)iovs_len;
  if (total_size >= UINT32_MAX ||
      !(ciovec_begin = (wasi_ciovec_t *)runtime_malloc((uint32_t)total_size)))
    return (wasi_errno_t)-1;

  ciovec = ciovec_begin;

  iovec_app_t *native_iovec_app =
      (iovec_app_t *)ADDR_APP_TO_NATIVE((uint32_t)(intptr_t)iovec_app);

  for (i = 0; i < iovs_len; i++, native_iovec_app++, ciovec++) {
    if (!VALIDATE_APP_ADDR(native_iovec_app->buf_offset,
                           native_iovec_app->buf_len)) {
      err = (wasi_errno_t)-1;
      runtime_free(ciovec_begin);
      return err;
    }
    ciovec->buf = (char *)ADDR_APP_TO_NATIVE(native_iovec_app->buf_offset);
    ciovec->buf_len = native_iovec_app->buf_len;
  }

  err = wasmtime_ssp_fd_pwrite(curfds, fd, ciovec_begin, iovs_len, offset,
                               &nwritten);
  if (err) {
    runtime_free(ciovec_begin);
    return err;
  }

  uint32_t *native_nwritten_app =
      (uint32_t *)ADDR_APP_TO_NATIVE((uint32_t)(intptr_t)nwritten_app);
  *native_nwritten_app = (uint32_t)nwritten;

  /* success */
  err = 0;

  runtime_free(ciovec_begin);
  return err;
}

static wasi_errno_t wasi_fd_read(Instance *instance, wasi_fd_t fd,
                                 const iovec_app_t *iovec_app,
                                 uint32_t iovs_len, uint32_t *nread_app) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);

  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);
  wasi_iovec_t *iovec, *iovec_begin;
  uint64_t total_size;
  size_t nread;
  uint32_t i;
  wasi_errno_t err;

  if (!wasi_ctx)
    return (wasi_errno_t)-1;
  VNMIEnv *vmenv = wasi_ctx->vnmi_env;

  total_size = sizeof(iovec_app_t) * (uint64_t)iovs_len;
  if (!VALIDATE_APP_ADDR((uint32_t)(intptr_t)nread_app,
                         (uint32_t)sizeof(uint32_t)) ||
      total_size >= UINT32_MAX ||
      !VALIDATE_APP_ADDR((uint32_t)(intptr_t)iovec_app, (uint32_t)total_size))
    return (wasi_errno_t)-1;

  total_size = sizeof(wasi_iovec_t) * (uint64_t)iovs_len;
  if (total_size >= UINT32_MAX ||
      !(iovec_begin = (wasi_iovec_t *)runtime_malloc((uint32_t)total_size)))
    return (wasi_errno_t)-1;

  iovec = iovec_begin;

  iovec_app_t *native_iovec_app =
      (iovec_app_t *)ADDR_APP_TO_NATIVE((uint32_t)(intptr_t)iovec_app);

  for (i = 0; i < iovs_len; i++, native_iovec_app++, iovec++) {
    if (!VALIDATE_APP_ADDR(native_iovec_app->buf_offset,
                           native_iovec_app->buf_len)) {
      err = (wasi_errno_t)-1;
      runtime_free(iovec_begin);
      return err;
    }
    iovec->buf = (void *)ADDR_APP_TO_NATIVE(native_iovec_app->buf_offset);
    iovec->buf_len = native_iovec_app->buf_len;
  }

  err = wasmtime_ssp_fd_read(curfds, fd, iovec_begin, iovs_len, &nread);
  if (err) {
    runtime_free(iovec_begin);
    return err;
  }

  uint32_t *native_nread_app =
      (uint32_t *)ADDR_APP_TO_NATIVE((uint32_t)(intptr_t)nread_app);
  *native_nread_app = (uint32_t)nread;

  /* success */
  err = 0;

  runtime_free(iovec_begin);
  return err;
}

static wasi_errno_t wasi_fd_renumber(Instance *instance, wasi_fd_t from,
                                     wasi_fd_t to) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);
  struct fd_prestats *prestats = wasi_ctx_get_prestats(instance, wasi_ctx);

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  return wasmtime_ssp_fd_renumber(curfds, prestats, from, to);
}

static wasi_errno_t wasi_fd_seek(Instance *instance, wasi_fd_t fd,
                                 wasi_filedelta_t offset, wasi_whence_t whence,
                                 wasi_filesize_t *newoffset) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  if (!VALIDATE_APP_ADDR((uint32_t)(intptr_t)newoffset,
                         sizeof(wasi_filesize_t)))
    return (wasi_errno_t)-1;

  wasi_filesize_t *native_newoffset =
      (wasi_filesize_t *)ADDR_APP_TO_NATIVE((uint32_t)(intptr_t)newoffset);
  return wasmtime_ssp_fd_seek(curfds, fd, offset, whence, native_newoffset);
}

static wasi_errno_t wasi_fd_tell(Instance *instance, wasi_fd_t fd,
                                 wasi_filesize_t *newoffset) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  if (!VALIDATE_APP_ADDR((uint32_t)(intptr_t)newoffset,
                         sizeof(wasi_filesize_t)))
    return (wasi_errno_t)-1;

  wasi_filesize_t *native_newoffset =
      (wasi_filesize_t *)ADDR_APP_TO_NATIVE((uint32_t)(intptr_t)newoffset);

  return wasmtime_ssp_fd_tell(curfds, fd, native_newoffset);
}

static wasi_errno_t wasi_fd_fdstat_get(Instance *instance, wasi_fd_t fd,
                                       wasi_fdstat_t *fdstat_app) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);
  wasi_fdstat_t fdstat;
  wasi_errno_t err;

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  if (!VALIDATE_APP_ADDR((uint32_t)(intptr_t)fdstat_app, sizeof(wasi_fdstat_t)))
    return (wasi_errno_t)-1;

  err = wasmtime_ssp_fd_fdstat_get(curfds, fd, &fdstat);
  if (err)
    return err;

  wasi_fdstat_t *native_fdstat_app =
      (wasi_fdstat_t *)ADDR_APP_TO_NATIVE((uint32_t)(intptr_t)fdstat_app);

  memcpy(native_fdstat_app, &fdstat, sizeof(wasi_fdstat_t));
  return 0;
}

static wasi_errno_t wasi_fd_fdstat_set_flags(Instance *instance, wasi_fd_t fd,
                                             wasi_fdflags_t flags) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  return wasmtime_ssp_fd_fdstat_set_flags(curfds, fd, flags);
}

static wasi_errno_t
wasi_fd_fdstat_set_rights(Instance *instance, wasi_fd_t fd,
                          wasi_rights_t fs_rights_base,
                          wasi_rights_t fs_rights_inheriting) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  return wasmtime_ssp_fd_fdstat_set_rights(curfds, fd, fs_rights_base,
                                           fs_rights_inheriting);
}

static wasi_errno_t wasi_fd_sync(Instance *instance, wasi_fd_t fd) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  return wasmtime_ssp_fd_sync(curfds, fd);
}

static wasi_errno_t wasi_fd_write(Instance *instance, wasi_fd_t fd,
                                  const iovec_app_t *iovec_app,
                                  uint32_t iovs_len, uint32_t *nwritten_app) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);

  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);
  wasi_ciovec_t *ciovec, *ciovec_begin;
  uint64_t total_size;
  size_t nwritten;
  uint32_t i;
  wasi_errno_t err;

  if (!wasi_ctx)
    return (wasi_errno_t)-1;
  VNMIEnv *vmenv = wasi_ctx->vnmi_env;

  total_size = sizeof(iovec_app_t) * (uint64_t)iovs_len;

  if (!VALIDATE_APP_ADDR((uint32_t)(uintptr_t)nwritten_app, sizeof(uint32_t)) ||
      total_size >= UINT32_MAX ||
      !VALIDATE_APP_ADDR((uint32_t)(uintptr_t)iovec_app, (uint32_t)total_size))
    return (wasi_errno_t)-1;

  total_size = sizeof(wasi_ciovec_t) * (uint64_t)iovs_len;
  if (total_size >= UINT32_MAX ||
      !(ciovec_begin = (wasi_ciovec_t *)runtime_malloc((uint32_t)total_size)))
    return (wasi_errno_t)-1;

  ciovec = ciovec_begin;

  iovec_app_t *native_iovec_app =
      (iovec_app_t *)ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)iovec_app);
  uint32_t *native_nwritten_app =
      (uint32_t *)ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)nwritten_app);

  for (i = 0; i < iovs_len; i++, native_iovec_app++, ciovec++) {
    if (!VALIDATE_APP_ADDR(native_iovec_app->buf_offset,
                           native_iovec_app->buf_len)) {
      err = (wasi_errno_t)-1;
      goto fail;
    }
    ciovec->buf = (char *)ADDR_APP_TO_NATIVE(native_iovec_app->buf_offset);
    ciovec->buf_len = native_iovec_app->buf_len;
  }

  err = wasmtime_ssp_fd_write(curfds, fd, ciovec_begin, iovs_len, &nwritten);
  if (err)
    goto fail;

  *native_nwritten_app = (uint32_t)nwritten;

  /* success */
  err = 0;

fail:
  runtime_free(ciovec_begin);
  return err;
}

static wasi_errno_t wasi_fd_advise(Instance *instance, wasi_fd_t fd,
                                   wasi_filesize_t offset, wasi_filesize_t len,
                                   wasi_advice_t advice) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  return wasmtime_ssp_fd_advise(curfds, fd, offset, len, advice);
}

static wasi_errno_t wasi_fd_allocate(Instance *instance, wasi_fd_t fd,
                                     wasi_filesize_t offset,
                                     wasi_filesize_t len) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  return wasmtime_ssp_fd_allocate(curfds, fd, offset, len);
}

static wasi_errno_t wasi_path_create_directory(Instance *instance, wasi_fd_t fd,
                                               const char *path,
                                               uint32_t path_len) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  if (!VALIDATE_APP_ADDR((uint32_t)(uintptr_t)path, path_len))
    return (wasi_errno_t)-1;

  char *native_path = (char *)ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)path);

  return wasmtime_ssp_path_create_directory(curfds, fd, native_path, path_len);
}

static wasi_errno_t wasi_path_link(Instance *instance, wasi_fd_t old_fd,
                                   wasi_lookupflags_t old_flags,
                                   const char *old_path, uint32_t old_path_len,
                                   wasi_fd_t new_fd, const char *new_path,
                                   uint32_t new_path_len) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);
  struct fd_prestats *prestats = wasi_ctx_get_prestats(instance, wasi_ctx);

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  if (!VALIDATE_APP_ADDR((uint32_t)(uintptr_t)old_path, old_path_len))
    return (wasi_errno_t)-1;

  if (!VALIDATE_APP_ADDR((uint32_t)(uintptr_t)new_path, new_path_len))
    return (wasi_errno_t)-1;

  char *native_old_path =
      (char *)ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)old_path);
  char *native_new_path =
      (char *)ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)new_path);

  return wasmtime_ssp_path_link(curfds, prestats, old_fd, old_flags,
                                native_old_path, old_path_len, new_fd,
                                native_new_path, new_path_len);
}

static wasi_errno_t
wasi_path_open(Instance *instance, wasi_fd_t dirfd, wasi_lookupflags_t dirflags,
               const char *path, uint32_t path_len, wasi_oflags_t oflags,
               wasi_rights_t fs_rights_base, wasi_rights_t fs_rights_inheriting,
               wasi_fdflags_t fs_flags, wasi_fd_t *fd_app) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);
  wasi_fd_t fd = (wasi_fd_t)-1; /* set fd_app -1 if path open failed */
  wasi_errno_t err;

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  if (!VALIDATE_APP_ADDR((uint32_t)(uintptr_t)path, path_len))
    return (wasi_errno_t)-1;

  if (!VALIDATE_APP_ADDR((uint32_t)(uintptr_t)fd_app, sizeof(wasi_fd_t)))
    return (wasi_errno_t)-1;

  char *native_path = (char *)ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)path);

  err = wasmtime_ssp_path_open(curfds, dirfd, dirflags, native_path, path_len,
                               oflags, fs_rights_base, fs_rights_inheriting,
                               fs_flags, &fd);

  wasi_fd_t *native_fd_app =
      (wasi_fd_t *)ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)fd_app);
  *native_fd_app = fd;
  return err;
}

static wasi_errno_t wasi_fd_readdir(Instance *instance, wasi_fd_t fd, void *buf,
                                    uint32_t buf_len, wasi_dircookie_t cookie,
                                    uint32_t *bufused_app) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);
  size_t bufused;
  wasi_errno_t err;

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  if (!VALIDATE_APP_ADDR((uint32_t)(uintptr_t)buf, buf_len))
    return (wasi_errno_t)-1;

  if (!VALIDATE_APP_ADDR((uint32_t)(uintptr_t)bufused_app, sizeof(uint32_t)))
    return (wasi_errno_t)-1;

  void *native_buf = ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)buf);

  err = wasmtime_ssp_fd_readdir(curfds, fd, native_buf, buf_len, cookie,
                                &bufused);
  if (err)
    return err;

  uint32_t *native_bufused_app =
      (uint32_t *)ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)bufused_app);

  *native_bufused_app = (uint32_t)bufused;
  return 0;
}

static wasi_errno_t wasi_path_readlink(Instance *instance, wasi_fd_t fd,
                                       const char *path, uint32_t path_len,
                                       char *buf, uint32_t buf_len,
                                       uint32_t *bufused_app) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);
  size_t bufused;
  wasi_errno_t err;

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  if (!VALIDATE_APP_ADDR((uint32_t)(uintptr_t)path, path_len))
    return (wasi_errno_t)-1;

  if (!VALIDATE_APP_ADDR((uint32_t)(uintptr_t)buf, buf_len))
    return (wasi_errno_t)-1;

  if (!VALIDATE_APP_ADDR((uint32_t)(uintptr_t)bufused_app, sizeof(uint32_t)))
    return (wasi_errno_t)-1;

  char *native_path = (char *)ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)path);
  void *native_buf = ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)buf);

  err = wasmtime_ssp_path_readlink(curfds, fd, native_path, path_len,
                                   (char *)native_buf, buf_len, &bufused);
  if (err)
    return err;

  uint32_t *native_bufused_app =
      (uint32_t *)ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)bufused_app);

  *native_bufused_app = (uint32_t)bufused;
  return 0;
}

static wasi_errno_t wasi_path_rename(Instance *instance, wasi_fd_t old_fd,
                                     const char *old_path,
                                     uint32_t old_path_len, wasi_fd_t new_fd,
                                     const char *new_path,
                                     uint32_t new_path_len) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  if (!VALIDATE_APP_ADDR((uint32_t)(uintptr_t)old_path, old_path_len))
    return (wasi_errno_t)-1;

  if (!VALIDATE_APP_ADDR((uint32_t)(uintptr_t)new_path, new_path_len))
    return (wasi_errno_t)-1;

  char *native_old_path =
      (char *)ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)old_path);
  char *native_new_path =
      (char *)ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)new_path);

  return wasmtime_ssp_path_rename(curfds, old_fd, native_old_path, old_path_len,
                                  new_fd, native_new_path, new_path_len);
}

static wasi_errno_t wasi_fd_filestat_get(Instance *instance, wasi_fd_t fd,
                                         wasi_filestat_t *filestat) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  if (!VALIDATE_APP_ADDR((uint32_t)(uintptr_t)filestat,
                         sizeof(wasi_filestat_t)))
    return (wasi_errno_t)-1;

  wasi_filestat_t *native_filestat =
      (wasi_filestat_t *)ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)filestat);

  return wasmtime_ssp_fd_filestat_get(curfds, fd, native_filestat);
}

static wasi_errno_t wasi_fd_filestat_set_times(Instance *instance, wasi_fd_t fd,
                                               wasi_timestamp_t st_atim,
                                               wasi_timestamp_t st_mtim,
                                               wasi_fstflags_t fstflags) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  return wasmtime_ssp_fd_filestat_set_times(curfds, fd, st_atim, st_mtim,
                                            fstflags);
}

static wasi_errno_t wasi_fd_filestat_set_size(Instance *instance, wasi_fd_t fd,
                                              wasi_filesize_t st_size) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  return wasmtime_ssp_fd_filestat_set_size(curfds, fd, st_size);
}

static wasi_errno_t wasi_path_filestat_get(Instance *instance, wasi_fd_t fd,
                                           wasi_lookupflags_t flags,
                                           const char *path, uint32_t path_len,
                                           wasi_filestat_t *filestat) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  if (!VALIDATE_APP_ADDR((uint32_t)(uintptr_t)path, path_len))
    return (wasi_errno_t)-1;

  if (!VALIDATE_APP_ADDR((uint32_t)(uintptr_t)filestat,
                         sizeof(wasi_filestat_t)))
    return (wasi_errno_t)-1;

  char *native_path = (char *)ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)path);
  wasi_filestat_t *native_filestat =
      (wasi_filestat_t *)ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)filestat);

  return wasmtime_ssp_path_filestat_get(curfds, fd, flags, native_path,
                                        path_len, native_filestat);
}

static wasi_errno_t wasi_path_filestat_set_times(
    Instance *instance, wasi_fd_t fd, wasi_lookupflags_t flags,
    const char *path, uint32_t path_len, wasi_timestamp_t st_atim,
    wasi_timestamp_t st_mtim, wasi_fstflags_t fstflags) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  if (!VALIDATE_APP_ADDR((uint32_t)(uintptr_t)path, path_len))
    return (wasi_errno_t)-1;

  char *native_path = (char *)ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)path);

  return wasmtime_ssp_path_filestat_set_times(
      curfds, fd, flags, native_path, path_len, st_atim, st_mtim, fstflags);
}

static wasi_errno_t wasi_path_symlink(Instance *instance, const char *old_path,
                                      uint32_t old_path_len, wasi_fd_t fd,
                                      const char *new_path,
                                      uint32_t new_path_len) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);
  struct fd_prestats *prestats = wasi_ctx_get_prestats(instance, wasi_ctx);

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  if (!VALIDATE_APP_ADDR((uint32_t)(uintptr_t)old_path, old_path_len))
    return (wasi_errno_t)-1;

  if (!VALIDATE_APP_ADDR((uint32_t)(uintptr_t)new_path, new_path_len))
    return (wasi_errno_t)-1;

  char *native_old_path =
      (char *)ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)old_path);
  char *native_new_path =
      (char *)ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)new_path);

  return wasmtime_ssp_path_symlink(curfds, prestats, native_old_path,
                                   old_path_len, fd, native_new_path,
                                   new_path_len);
}

static wasi_errno_t wasi_path_unlink_file(Instance *instance, wasi_fd_t fd,
                                          const char *path, uint32_t path_len) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  if (!VALIDATE_APP_ADDR((uint32_t)(uintptr_t)path, path_len))
    return (wasi_errno_t)-1;

  char *native_path = (char *)ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)path);

  return wasmtime_ssp_path_unlink_file(curfds, fd, native_path, path_len);
}

static wasi_errno_t wasi_path_remove_directory(Instance *instance, wasi_fd_t fd,
                                               const char *path,
                                               uint32_t path_len) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  if (!VALIDATE_APP_ADDR((uint32_t)(uintptr_t)path, path_len))
    return (wasi_errno_t)-1;

  char *native_path = (char *)ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)path);

  return wasmtime_ssp_path_remove_directory(curfds, fd, native_path, path_len);
}

static wasi_errno_t wasi_poll_oneoff(Instance *instance,
                                     const wasi_subscription_t *in,
                                     wasi_event_t *out, uint32_t nsubscriptions,
                                     uint32_t *nevents_app) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);
  size_t nevents;
  wasi_errno_t err;

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  if (!VALIDATE_APP_ADDR((uint32_t)(uintptr_t)in,
                         sizeof(wasi_subscription_t)) ||
      !VALIDATE_APP_ADDR((uint32_t)(uintptr_t)out, sizeof(wasi_event_t)) ||
      !VALIDATE_APP_ADDR((uint32_t)(uintptr_t)nevents_app, sizeof(uint32_t)))
    return (wasi_errno_t)-1;

  wasi_subscription_t *native_in =
      (wasi_subscription_t *)ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)in);
  wasi_event_t *native_out =
      (wasi_event_t *)ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)out);

  err = wasmtime_ssp_poll_oneoff(curfds, native_in, native_out, nsubscriptions,
                                 &nevents);
  if (err)
    return err;

  uint32_t *native_events_app =
      (uint32_t *)ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)nevents_app);
  *native_events_app = (uint32_t)nevents;
  return 0;
}

static void wasi_proc_exit(Instance *instance, wasi_exitcode_t exit_code) {
  using namespace common;
  /* Here throwing exception is just to let wasm app exit,
     the upper layer should clear the exception and return
     as normal */
  instance->exit(exit_code);
}

static wasi_errno_t wasi_proc_raise(Instance *instance, wasi_signal_t sig) {
  using namespace common;
  instance->setExceptionByHostapi(
      getErrorWithExtraMessage(ErrorCode::WASIProcRaise, std::to_string(sig)));
  return 0;
}

static wasi_errno_t wasi_random_get(Instance *instance, void *buf,
                                    uint32_t buf_len) {
  if (!VALIDATE_APP_ADDR((uint32_t)(uintptr_t)buf, buf_len))
    return (wasi_errno_t)-1;

  void *native_buf = ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)buf);
  return wasmtime_ssp_random_get(native_buf, buf_len);
}

static wasi_errno_t wasi_sock_recv(Instance *instance, wasi_fd_t sock,
                                   iovec_app_t *ri_data, uint32_t ri_data_len,
                                   wasi_riflags_t ri_flags,
                                   uint32_t *ro_datalen_app,
                                   wasi_roflags_t *ro_flags) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);

  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);
  wasi_iovec_t *iovec, *iovec_begin;
  uint64_t total_size;
  size_t ro_datalen;
  uint32_t i;
  wasi_errno_t err;

  if (!wasi_ctx)
    return (wasi_errno_t)-1;
  VNMIEnv *vmenv = wasi_ctx->vnmi_env;

  total_size = sizeof(iovec_app_t) * (uint64_t)ri_data_len;
  if (!VALIDATE_APP_ADDR((uint32_t)(uintptr_t)ro_datalen_app,
                         (uint32_t)sizeof(uint32_t)) ||
      !VALIDATE_APP_ADDR((uint32_t)(uintptr_t)ro_flags,
                         (uint32_t)sizeof(wasi_roflags_t)) ||
      total_size >= UINT32_MAX ||
      !VALIDATE_APP_ADDR((uint32_t)(uintptr_t)ri_data, (uint32_t)total_size))
    return (wasi_errno_t)-1;

  total_size = sizeof(wasi_iovec_t) * (uint64_t)ri_data_len;
  if (total_size >= UINT32_MAX ||
      !(iovec_begin = (wasi_iovec_t *)runtime_malloc((uint32_t)total_size)))
    return (wasi_errno_t)-1;

  iovec = iovec_begin;

  iovec_app_t *native_ri_data =
      (iovec_app_t *)ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)ri_data);
  for (i = 0; i < ri_data_len; i++, native_ri_data++, iovec++) {
    if (!VALIDATE_APP_ADDR(native_ri_data->buf_offset,
                           native_ri_data->buf_len)) {
      err = (wasi_errno_t)-1;
      runtime_free(iovec_begin);
      return err;
    }
    iovec->buf = (void *)ADDR_APP_TO_NATIVE(native_ri_data->buf_offset);
    iovec->buf_len = native_ri_data->buf_len;
  }

  wasi_roflags_t *native_ro_flags =
      (wasi_roflags_t *)ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)ro_flags);
  err = wasmtime_ssp_sock_recv(curfds, sock, iovec_begin, ri_data_len, ri_flags,
                               &ro_datalen, native_ro_flags);
  if (err) {
    runtime_free(iovec_begin);
    return err;
  }

  uint32_t *native_ro_datalen_app =
      (uint32_t *)ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)ro_datalen_app);

  *(uint32_t *)native_ro_datalen_app = (uint32_t)ro_datalen;

  /* success */
  err = 0;

  runtime_free(iovec_begin);
  return err;
}

static wasi_errno_t wasi_sock_send(Instance *instance, wasi_fd_t sock,
                                   const iovec_app_t *si_data,
                                   uint32_t si_data_len,
                                   wasi_siflags_t si_flags,
                                   uint32_t *so_datalen_app) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);

  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);
  wasi_ciovec_t *ciovec, *ciovec_begin;
  uint64_t total_size;
  size_t so_datalen;
  uint32_t i;
  wasi_errno_t err;

  if (!wasi_ctx)
    return (wasi_errno_t)-1;
  VNMIEnv *vmenv = wasi_ctx->vnmi_env;

  total_size = sizeof(iovec_app_t) * (uint64_t)si_data_len;
  if (!VALIDATE_APP_ADDR((uint32_t)(uintptr_t)so_datalen_app,
                         sizeof(uint32_t)) ||
      total_size >= UINT32_MAX ||
      !VALIDATE_APP_ADDR((uint32_t)(uintptr_t)si_data, (uint32_t)total_size))
    return (wasi_errno_t)-1;

  total_size = sizeof(wasi_ciovec_t) * (uint64_t)si_data_len;
  if (total_size >= UINT32_MAX ||
      !(ciovec_begin = (wasi_ciovec_t *)runtime_malloc((uint32_t)total_size)))
    return (wasi_errno_t)-1;

  ciovec = ciovec_begin;

  iovec_app_t *native_si_data =
      (iovec_app_t *)ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)si_data);

  for (i = 0; i < si_data_len; i++, native_si_data++, ciovec++) {
    if (!VALIDATE_APP_ADDR(native_si_data->buf_offset,
                           native_si_data->buf_len)) {
      err = (wasi_errno_t)-1;
      runtime_free(ciovec_begin);
      return err;
    }
    ciovec->buf = (char *)ADDR_APP_TO_NATIVE(native_si_data->buf_offset);
    ciovec->buf_len = native_si_data->buf_len;
  }

  err = wasmtime_ssp_sock_send(curfds, sock, ciovec_begin, si_data_len,
                               si_flags, &so_datalen);
  if (err) {
    runtime_free(ciovec_begin);
    return err;
  }

  uint32_t *native_so_datalen_app =
      (uint32_t *)ADDR_APP_TO_NATIVE((uint32_t)(uintptr_t)so_datalen_app);

  *native_so_datalen_app = (uint32_t)so_datalen;

  /* success */
  err = 0;

  runtime_free(ciovec_begin);
  return err;
}

static wasi_errno_t wasi_sock_shutdown(Instance *instance, wasi_fd_t sock,
                                       wasi_sdflags_t how) {
  wasi_ctx_t wasi_ctx = getNativeCtxFromInstance(instance);
  struct fd_table *curfds = wasi_ctx_get_curfds(instance, wasi_ctx);

  if (!wasi_ctx)
    return (wasi_errno_t)-1;

  return wasmtime_ssp_sock_shutdown(curfds, sock, how);
}

static wasi_errno_t wasi_sched_yield(Instance *instance) {
  return wasmtime_ssp_sched_yield();
}

// ======================== [End] WASI Functions ========================
// RESERVED_FUNC_ENTRY means this function is a vm reserved function, VM may
// call it by its name and signature.

#define FUNCTION_LISTS                                                         \
  RESERVED_FUNC_ENTRY(vnmi_init_ctx)                                           \
  RESERVED_FUNC_ENTRY(vnmi_destroy_ctx)                                        \
  NATIVE_FUNC_ENTRY(args_get)                                                  \
  NATIVE_FUNC_ENTRY(args_sizes_get)                                            \
  NATIVE_FUNC_ENTRY(clock_res_get)                                             \
  NATIVE_FUNC_ENTRY(clock_time_get)                                            \
  NATIVE_FUNC_ENTRY(environ_get)                                               \
  NATIVE_FUNC_ENTRY(environ_sizes_get)                                         \
  NATIVE_FUNC_ENTRY(fd_prestat_get)                                            \
  NATIVE_FUNC_ENTRY(fd_prestat_dir_name)                                       \
  NATIVE_FUNC_ENTRY(fd_close)                                                  \
  NATIVE_FUNC_ENTRY(fd_datasync)                                               \
  NATIVE_FUNC_ENTRY(fd_pread)                                                  \
  NATIVE_FUNC_ENTRY(fd_pwrite)                                                 \
  NATIVE_FUNC_ENTRY(fd_read)                                                   \
  NATIVE_FUNC_ENTRY(fd_renumber)                                               \
  NATIVE_FUNC_ENTRY(fd_seek)                                                   \
  NATIVE_FUNC_ENTRY(fd_tell)                                                   \
  NATIVE_FUNC_ENTRY(fd_fdstat_get)                                             \
  NATIVE_FUNC_ENTRY(fd_fdstat_set_flags)                                       \
  NATIVE_FUNC_ENTRY(fd_fdstat_set_rights)                                      \
  NATIVE_FUNC_ENTRY(fd_sync)                                                   \
  NATIVE_FUNC_ENTRY(fd_write)                                                  \
  NATIVE_FUNC_ENTRY(fd_advise)                                                 \
  NATIVE_FUNC_ENTRY(fd_allocate)                                               \
  NATIVE_FUNC_ENTRY(path_create_directory)                                     \
  NATIVE_FUNC_ENTRY(path_link)                                                 \
  NATIVE_FUNC_ENTRY(path_open)                                                 \
  NATIVE_FUNC_ENTRY(fd_readdir)                                                \
  NATIVE_FUNC_ENTRY(path_readlink)                                             \
  NATIVE_FUNC_ENTRY(path_rename)                                               \
  NATIVE_FUNC_ENTRY(fd_filestat_get)                                           \
  NATIVE_FUNC_ENTRY(fd_filestat_set_times)                                     \
  NATIVE_FUNC_ENTRY(fd_filestat_set_size)                                      \
  NATIVE_FUNC_ENTRY(path_filestat_get)                                         \
  NATIVE_FUNC_ENTRY(path_filestat_set_times)                                   \
  NATIVE_FUNC_ENTRY(path_symlink)                                              \
  NATIVE_FUNC_ENTRY(path_unlink_file)                                          \
  NATIVE_FUNC_ENTRY(path_remove_directory)                                     \
  NATIVE_FUNC_ENTRY(poll_oneoff)                                               \
  NATIVE_FUNC_ENTRY(proc_exit)                                                 \
  NATIVE_FUNC_ENTRY(proc_raise)                                                \
  NATIVE_FUNC_ENTRY(random_get)                                                \
  NATIVE_FUNC_ENTRY(sock_recv)                                                 \
  NATIVE_FUNC_ENTRY(sock_send)                                                 \
  NATIVE_FUNC_ENTRY(sock_shutdown)                                             \
  NATIVE_FUNC_ENTRY(sched_yield)

// Alias wasi functions without 'wasi_' prefix
// Don't copy the following three lines unless you understand it completely.
#define RESERVED_FUNC_ENTRY(name)
#define NATIVE_FUNC_ENTRY(name) constexpr const auto name = wasi_##name;
FUNCTION_LISTS
#undef NATIVE_FUNC_ENTRY
#undef RESERVED_FUNC_ENTRY

/*
  the following code are auto generated,
  don't modify it unless you know it exactly.
*/
#include "wni/boilerplate.cpp"

} // namespace zen::host
