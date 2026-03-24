use std::path::Path;

use libloading::Library;
use once_cell::sync::OnceCell;

pub struct CdmLibrary {
    _lib: Library,

    // symbols
    pub initialize_cdm_module: usize,
    pub deinitialize_cdm_module: usize,
    pub get_cdm_version: usize,
    pub verify_cdm_host: usize,
    pub create_cdm_instance: usize,
}

static CDM: OnceCell<CdmLibrary> = OnceCell::new();

pub fn initialize_cdm(path: impl AsRef<Path>) -> Result<&'static CdmLibrary, libloading::Error> {
    let cdm = CDM.get_or_try_init(|| unsafe {
        let lib = Library::new(path.as_ref())?;

        let initialize_cdm_module: usize = *lib.get(b"InitializeCdmModule_4\0")?;
        let deinitialize_cdm_module: usize = *lib.get(b"DeinitializeCdmModule\0")?;
        let get_cdm_version: usize = *lib.get(b"GetCdmVersion\0")?;
        let verify_cdm_host: usize = *lib.get(b"VerifyCdmHost_0\0")?;
        let create_cdm_instance: usize = *lib.get(b"CreateCdmInstance\0")?;

        Ok(CdmLibrary {
            _lib: lib,
            initialize_cdm_module,
            deinitialize_cdm_module,
            get_cdm_version,
            verify_cdm_host,
            create_cdm_instance,
        })
    })?;

    Ok(cdm)
}

pub fn get_cdm() -> Option<&'static CdmLibrary> {
    CDM.get()
}
