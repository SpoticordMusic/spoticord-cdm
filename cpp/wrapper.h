#pragma once

#include "cdm/content_decryption_module.h"

extern "C" {
void rs_on_initialized(void *context, bool success);
void rs_on_resolve_promise(void *context, uint32_t promise_id);
void rs_on_resolve_session_promise(void *context, uint32_t promise_id,
                                   const char *session_id,
                                   uint32_t session_id_size);
void rs_on_reject_promise(void *context, uint32_t promise_id,
                          cdm::Exception exception, uint32_t system_code,
                          const char *error_message,
                          uint32_t error_message_size);
void rs_on_session_message(void *context, const char *session_id,
                           uint32_t session_id_size,
                           cdm::MessageType message_type, const char *message,
                           uint32_t message_size);
void rs_on_session_keys_change(void *context, const char *session_id,
                               uint32_t session_id_size,
                               bool has_additional_usable_key,
                               const cdm::KeyInformation *keys_info,
                               uint32_t keys_info_count);
}