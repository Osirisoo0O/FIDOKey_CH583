/**
 * @file storage.c
 * @brief 存储后端注册与分发（与具体介质无关）
 *
 * 具体后端见 storage_eeprom.c（片内 DataFlash）；
 * 将来接 SPI NOR 时新增 storage_spinor.c 并在 secure_store_init 里改注册即可，
 * 上层（secure_store / cred_mgr / ctap）无需改动。
 */

#include "stdint.h"
#include "string.h"      /* NULL */
#include "storage.h"

static const storage_backend_t *s_backend = NULL;

int8_t storage_init(const storage_backend_t *backend)
{
    if(backend == NULL)
    {
        return -1;
    }
    if(backend->erase_size == 0 || backend->capacity == 0)
    {
        return -1;
    }
    if(backend->read == NULL || backend->write == NULL || backend->erase == NULL)
    {
        return -1;
    }

    s_backend = backend;

    return (backend->init != NULL) ? backend->init() : 0;
}

const storage_backend_t *storage_get(void)
{
    return s_backend;
}
