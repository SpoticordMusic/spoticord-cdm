#include "wrapper.h"
#include "adapter.h"
#include "cdm/content_decryption_module.h"
#include <cstdint>

static void *GetCdmHost(int aHostInterfaceVersion, void *aUserData) {
  auto *host = reinterpret_cast<WidevineAdapter *>(aUserData);

  return static_cast<cdm::Host_11 *>(host);
}

extern "C" {
void cdm_module_initialize(void *proc) {
  const auto initCdmModule =
      reinterpret_cast<decltype(::INITIALIZE_CDM_MODULE) *>(proc);

  initCdmModule();
}

const char *cdm_get_version(void *proc) {
  const auto getCdmVersion =
      reinterpret_cast<decltype(::GetCdmVersion) *>(proc);

  return getCdmVersion();
}

cdm::Host_11 *cdm_create_host(void *context) {
  auto adapter = new WidevineAdapter(context);

  return static_cast<cdm::Host_11 *>(adapter);
}

void *cdm_create_instance(void *proc, cdm::Host_11 *host) {
  const auto createCdmInstance =
      reinterpret_cast<decltype(::CreateCdmInstance) *>(proc);
  const auto cdm = reinterpret_cast<cdm::ContentDecryptionModule_11 *>(
      createCdmInstance(cdm::ContentDecryptionModule_11::kVersion,
                        "com.widevine.alpha", 18, &GetCdmHost, host));

  if (!cdm) {
    return nullptr;
  }

  return cdm;
}

void cdm_instance_initialize(cdm::ContentDecryptionModule_11 *cdm,
                             bool allow_distinctive_identifier,
                             bool allow_persistent_state,
                             bool use_hw_secure_codecs) {
  cdm->Initialize(allow_distinctive_identifier, allow_persistent_state,
                  use_hw_secure_codecs);
}

void cdm_set_server_certificate(cdm::ContentDecryptionModule_11 *cdm,
                                uint32_t promise_id,
                                const uint8_t *server_certificate_data,
                                uint32_t server_certificate_data_size) {
  cdm->SetServerCertificate(promise_id, server_certificate_data,
                            server_certificate_data_size);
}

void cdm_create_session(cdm::ContentDecryptionModule_11 *cdm,
                        uint32_t promise_id, const uint8_t *init_data,
                        uint32_t init_data_size) {
  cdm->CreateSessionAndGenerateRequest(promise_id, cdm::SessionType::kTemporary,
                                       cdm::InitDataType::kCenc, init_data,
                                       init_data_size);
}

void cdm_update_session(cdm::ContentDecryptionModule_11 *cdm,
                        uint32_t promise_id, const char *session_id,
                        uint32_t session_id_size, const uint8_t *response,
                        uint32_t response_size) {
  cdm->UpdateSession(promise_id, session_id, session_id_size, response,
                     response_size);
}

cdm::Status cdm_session_decrypt(cdm::ContentDecryptionModule_11 *cdm,
                                const cdm::InputBuffer_2 &encrypted_buffer,
                                WidevineDecryptedBlock **decrypted_buffer) {
  WidevineDecryptedBlock *block = new WidevineDecryptedBlock();
  cdm::Status result = cdm->Decrypt(encrypted_buffer, block);

  *decrypted_buffer = block;

  return result;
}

void cdm_close_session(cdm::ContentDecryptionModule_11 *cdm,
                       uint32_t promise_id, const char *session_id,
                       uint32_t session_id_size) {
  cdm->CloseSession(promise_id, session_id, session_id_size);
}

void cdm_decrypted_block_data(WidevineDecryptedBlock *block, uint8_t **data,
                              uint32_t *data_size) {
  *data = block->DecryptedBuffer()->Data();
  *data_size = block->DecryptedBuffer()->Size();
}

void cdm_decrypted_block_free(WidevineDecryptedBlock *block) { delete block; }
}