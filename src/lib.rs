use rabe::schemes::*;
use bincode;
use std::ffi::CString;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr::null;
use std::ptr::null_mut;
use base64::prelude::*;

#[cfg(test)]
mod tests {
    use rabe::schemes::*;
    use rabe::utils::policy::pest::PolicyLanguage;

    #[test]
    fn test_bsw_cpabe() {
        let (pk, msk) = bsw::setup();
        let plaintext =
            String::from("dance like no one's watching, encrypt like everyone is!").into_bytes();
        let policy = String::from(r#""A" and "B""#);
        let ct_cp: bsw::CpAbeCiphertext =
            bsw::encrypt(&pk, &policy, &plaintext, PolicyLanguage::HumanPolicy).unwrap();
        let sk: bsw::CpAbeSecretKey =
            bsw::keygen(&pk, &msk, &vec!["A".to_string(), "B".to_string()]).unwrap();
        assert_eq!(bsw::decrypt(&sk, &ct_cp).unwrap(), plaintext);
    }

    #[test]
    fn test_lsw_kpabe() {
        let (pk, msk) = lsw::setup();
        let plaintext = String::from("our plaintext!").into_bytes();
        let policy = String::from(r#""X" or "B""#);
        let ct_kp: lsw::KpAbeCiphertext =
            lsw::encrypt(&pk, &vec!["A".to_string(), "B".to_string()], &plaintext).unwrap();
        let sk: lsw::KpAbeSecretKey =
            lsw::keygen(&pk, &msk, &policy, PolicyLanguage::HumanPolicy).unwrap();
        assert_eq!(lsw::decrypt(&sk, &ct_kp).unwrap(), plaintext);
    }
}

#[no_mangle]
pub extern "C" fn cp_setup(p_pk: *mut bsw::CpAbePublicKey, p_msk: *mut bsw::CpAbeMasterKey) {
    let (pk, msk) = bsw::setup();
    unsafe {
        *p_pk = pk;
        *p_msk = msk;
    }
}

#[no_mangle]
pub extern "C" fn cp_keygen(
    p_pk: *const bsw::CpAbePublicKey,
    p_msk: *const bsw::CpAbeMasterKey,
    p_attributes: *const *mut c_char,
    n_attributes: u32,
) -> *mut i8 {
    unsafe {
        let c_attrs = std::slice::from_raw_parts(p_attributes, n_attributes as usize);
        let attrs: Vec<_> = c_attrs
            .iter()
            .map(|raw| String::from(CStr::from_ptr(*raw).to_str().unwrap_or_default()))
            .collect();
        let sk = bsw::keygen(&*p_pk, &*p_msk, &attrs);
        if sk.is_some() {
            let encoded: Vec<u8> = bincode::serialize(&sk.unwrap()).unwrap();

            let ret = CString::new(encoded).unwrap();
            return ret.into_raw();
        } else {
            return null_mut();
        }
    };
}

// encrypt, decrypt, delegate