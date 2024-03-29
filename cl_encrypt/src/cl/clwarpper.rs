extern crate libc;

use libc::c_char;
use std::ffi::{CString, CStr};
use encoding::{DecoderTrap, Encoding};
use encoding::all::GBK;

static HEX_TABLE :[char;16] = ['0','1','2','3','4','5','6','7','8','9',
                                        'A','B','C','D','E','F'];

#[link(name = "encrypt")]
extern "C" {
    pub fn public_key_gen_cpp(sk_str: *const c_char) -> *const c_char;
    pub fn encrypt_cpp(pk_str: *const c_char, message: *const c_char, random: *const c_char) -> *const c_char;
    pub fn decrypt_cpp(sk_str: *const c_char, cipher_str: *const c_char) -> *const c_char;
    pub fn encrypt_enc_cpp(pk_str: *const c_char, message: *const c_char, random: *const c_char) -> *const c_char;
    pub fn decrypt_enc_cpp(sk_str: *const c_char, cipher_str: *const c_char) -> *const c_char;
    pub fn add_ciphertexts_cpp(cipher_str_first: *const c_char, cipher_str_second: *const c_char) -> *const c_char;
    pub fn add_ciphertexts_enc_cpp(cipher_str_first: *const c_char, cipher_str_second: *const c_char) -> *const c_char;
    pub fn scal_ciphertexts_cpp(cipher_str: *const c_char, m_str: *const c_char) -> *const c_char;
    pub fn cl_ecc_prove_cpp(pk_str: *const c_char, cipher_str: *const c_char , commit_str: *const c_char, m_str: *const c_char, r_str: *const c_char) -> *const c_char;
    pub fn cl_ecc_verify_cpp(proof_str: *const c_char, pk_str: *const c_char, cipher_str: *const c_char , commit_str: *const c_char) -> *const c_char;
    pub fn cl_enc_com_prove_cpp(pk_str: *const c_char, cipher_str: *const c_char , commit_str: *const c_char, m_str: *const c_char, r_str: *const c_char) -> *const c_char;
    pub fn cl_enc_com_verify_cpp(proof_str: *const c_char, pk_str: *const c_char, cipher_str: *const c_char , commit_str: *const c_char) -> *const c_char;
    pub fn power_of_h_cpp(x_str: *const c_char) -> *const c_char;
    pub fn calculate_commit_cpp(x_str: *const c_char, delta_str: *const c_char) -> *const c_char;
    pub fn calculate_commitments_cpp(coefficients_str: *const c_char, delta_str: *const c_char) -> *const c_char;
    pub fn verify_share_cpp(commitments_str: *const c_char, secret_share_str: *const c_char, index_str: *const c_char, delta_str: *const c_char) -> *const c_char;
    pub fn verify_share_commit_cpp(commitments_str: *const c_char, share_commit_str: *const c_char, index_str: *const c_char, delta_str: *const c_char) -> *const c_char;
    pub fn qfi_add_cpp(qfi1_str: *const c_char, qfi2_str: *const c_char) -> *const c_char;
    // pub fn qfi_add_hash_cpp(qfi1_str: *const c_char, qfi2_str: *const c_char) -> *const c_char;
    pub fn qfi_mul_cpp(qfi: *const c_char, mpz: *const c_char) -> *const c_char;
    // pub fn qfi_mul_hash_cpp(qfi: *const c_char, mpz: *const c_char) -> *const c_char;
    pub fn get_qfi_zero_cpp() -> *const c_char;
    pub fn decrypt_c1_cpp(cipher_str: *const c_char, sk_str: *const c_char, delta_str: *const c_char) -> *const c_char;
    pub fn multi_decrypt_cpp(c1_str: *const c_char, cipher_str: *const c_char, delta_str: *const c_char) -> *const c_char;
    pub fn pre_calculate_pk_cpp(pk_str: *const c_char) -> *const c_char;
}

pub fn c_char_decode(input: *const i8) -> String {
    unsafe{
        let mut msgstr: String = "".to_string();
        if input != (0 as *mut c_char) {
            let errcstr = CStr::from_ptr(input);
            let errcstr_tostr = errcstr.to_str();
            //这里要处理下编码，rust默认是UTF-8,如果不ok，那就是其他字符集
            if errcstr_tostr.is_ok() {
                msgstr = errcstr_tostr.unwrap().to_string();
            } else {
                //强行尝试对CStr对象进行GBK解码,采用replace策略
                //todo: 如果在使用其他编码的平台上依旧有可能失败，得到空消息，但不会抛异常了
                let alter_msg = GBK.decode(errcstr.to_bytes(), DecoderTrap::Replace);
                // let alter_msg = encoding::all::UTF_8.decode(errcstr.to_bytes(),DecoderTrap::Replace);
                if alter_msg.is_ok() {
                    msgstr = alter_msg.unwrap();
                }
            }
        }
        return msgstr;
    }
    
}

pub fn public_key_gen(sk: String) -> String {
    let sk_str = CString::new(sk).unwrap();
    unsafe{
        return c_char_decode(public_key_gen_cpp(sk_str.as_ptr()));
    }
}

pub fn encrypt(pk: String, message: String, random: String) -> String{
    let pk_str = CString::new(pk).unwrap();
    let m_str = CString::new(message).unwrap();
    let r_str = CString::new(random).unwrap();
    unsafe{
        return c_char_decode(encrypt_cpp(pk_str.as_ptr(), m_str.as_ptr(), r_str.as_ptr()));
    }
}

pub fn decrypt(sk: String, cipher: String) -> String{
    let sk_str = CString::new(sk).unwrap();
    let c_str = CString::new(cipher).unwrap();
    unsafe{
        return c_char_decode(decrypt_cpp(sk_str.as_ptr(), c_str.as_ptr()));
    }
}

pub fn encrypt_enc(pk: String, message: String, random: String) -> String{
    let pk_str = CString::new(pk).unwrap();
    let m_str = CString::new(message).unwrap();
    let r_str = CString::new(random).unwrap();
    unsafe{
        return c_char_decode(encrypt_enc_cpp(pk_str.as_ptr(), m_str.as_ptr(), r_str.as_ptr()));
    }
}

pub fn decrypt_enc(sk: String, cipher: String) -> String{
    let sk_str = CString::new(sk).unwrap();
    let c_str = CString::new(cipher).unwrap();
    unsafe{
        return c_char_decode(decrypt_enc_cpp(sk_str.as_ptr(), c_str.as_ptr()));
    }
}

pub fn add_ciphertexts(cipher_first: String, cipher_second: String) -> String{
    let c_first_str = CString::new(cipher_first).unwrap();
    let c_second_str = CString::new(cipher_second).unwrap();
    unsafe{
        return c_char_decode(add_ciphertexts_cpp(c_first_str.as_ptr(), c_second_str.as_ptr()));
    }
}

pub fn add_ciphertexts_enc(cipher_first: String, cipher_second: String) -> String{
    let c_first_str = CString::new(cipher_first).unwrap();
    let c_second_str = CString::new(cipher_second).unwrap();
    unsafe{
        return c_char_decode(add_ciphertexts_enc_cpp(c_first_str.as_ptr(), c_second_str.as_ptr()));
    }
}

pub fn scal_ciphertexts(cipher: String, message: String) -> String{
    let c_str = CString::new(cipher).unwrap();
    let m_str = CString::new(message).unwrap();
    unsafe{
        return c_char_decode(scal_ciphertexts_cpp(c_str.as_ptr(), m_str.as_ptr()));
    }
}

pub fn cl_ecc_prove(pk: String, cipher: String, commit: String, message: String, random: String)-> String{
    let pk_str= CString::new(pk).unwrap();
    let c_str =  CString::new(cipher).unwrap();
    let commit_str =  CString::new(commit).unwrap();
    let m_str =  CString::new(message).unwrap();
    let r_str =  CString::new(random).unwrap();
    unsafe{
        return c_char_decode(cl_ecc_prove_cpp(pk_str.as_ptr(), c_str.as_ptr(), commit_str.as_ptr(), m_str.as_ptr(), r_str.as_ptr()));
    }
}

pub fn cl_ecc_verify(proof: String, pk: String, cipher: String, commit: String)-> String{
    let proof_str = CString::new(proof).unwrap();
    let pk_str= CString::new(pk).unwrap();
    let c_str =  CString::new(cipher).unwrap();
    let commit_str =  CString::new(commit).unwrap();
    unsafe{
        return c_char_decode(cl_ecc_verify_cpp(proof_str.as_ptr(), pk_str.as_ptr(), c_str.as_ptr(), commit_str.as_ptr()));
    }
}

pub fn cl_enc_com_prove(pk: String, cipher: String, commit: String, message: String, random: String)-> String{
    let pk_str= CString::new(pk).unwrap();
    let c_str =  CString::new(cipher).unwrap();
    let commit_str =  CString::new(commit).unwrap();
    let m_str =  CString::new(message).unwrap();
    let r_str =  CString::new(random).unwrap();
    unsafe{
        return c_char_decode(cl_enc_com_prove_cpp(pk_str.as_ptr(), c_str.as_ptr(), commit_str.as_ptr(), m_str.as_ptr(), r_str.as_ptr()));
    }
}

pub fn cl_enc_com_verify(proof: String, pk: String, cipher: String, commit: String)-> String{
    let proof_str = CString::new(proof).unwrap();
    let pk_str= CString::new(pk).unwrap();
    let c_str =  CString::new(cipher).unwrap();
    let commit_str =  CString::new(commit).unwrap();
    unsafe{
        return c_char_decode(cl_enc_com_verify_cpp(proof_str.as_ptr(), pk_str.as_ptr(), c_str.as_ptr(), commit_str.as_ptr()));
    }
}

pub fn power_of_h(x: String)-> String{
    let x_str = CString::new(x).unwrap();
    unsafe{
        return c_char_decode(power_of_h_cpp(x_str.as_ptr()));
    }
}

pub fn calculate_commit(x: String, delta: String)-> String{
    let x_str = CString::new(x).unwrap();
    let delta_str = CString::new(delta).unwrap();
    unsafe{
        return c_char_decode(calculate_commit_cpp(x_str.as_ptr(), delta_str.as_ptr()));
    }
}

pub fn calculate_commitments(coefficient: String, delta: String)-> String{
    let coefficient_str = CString::new(coefficient).unwrap();
    let delta_str = CString::new(delta).unwrap();
    unsafe{
        return c_char_decode(calculate_commitments_cpp(coefficient_str.as_ptr(), delta_str.as_ptr()));
    }
}

pub fn qfi_add(qfi1: String, qfi2: &String)-> String{
    let qfi1_str = CString::new(qfi1.to_string()).unwrap();
    let qfi2_str = CString::new(qfi2.to_string()).unwrap();
    unsafe{
        return c_char_decode(qfi_add_cpp(qfi1_str.as_ptr(), qfi2_str.as_ptr()));
    }
}

// pub fn qfi_add_hash(qfi1: String, qfi2: &String)-> String{
//     let qfi1_str = CString::new(qfi1.to_string()).unwrap();
//     let qfi2_str = CString::new(qfi2.to_string()).unwrap();
//     unsafe{
//         return c_char_decode(qfi_add_hash_cpp(qfi1_str.as_ptr(), qfi2_str.as_ptr()));
//     }
// }

pub fn qfi_mul(qfi: String, mpz: String)-> String{
    let qfi_str = CString::new(qfi).unwrap();
    let mpz_str = CString::new(mpz).unwrap();
    unsafe{
        return c_char_decode(qfi_mul_cpp(qfi_str.as_ptr(), mpz_str.as_ptr()));
    }
}

// pub fn qfi_mul_hash(qfi: String, mpz: String)-> String{
//     let qfi_str = CString::new(qfi).unwrap();
//     let mpz_str = CString::new(mpz).unwrap();
//     unsafe{
//         return c_char_decode(qfi_mul_hash_cpp(qfi_str.as_ptr(), mpz_str.as_ptr()));
//     }
// }

pub fn verify_share(commitments: String, secret_share: String, index: String, delta: String) -> String{
    let commitments_str = CString::new(commitments).unwrap();
    let secret_share_str = CString::new(secret_share).unwrap();
    let index_str = CString::new(index).unwrap();
    let delta_str =  CString::new(delta).unwrap();
    unsafe{
        return c_char_decode(verify_share_cpp(commitments_str.as_ptr(), secret_share_str.as_ptr(), index_str.as_ptr(), delta_str.as_ptr()));
    }
}

pub fn verify_share_commit(commitments: String, share_commit: String, index: String, delta: String) -> String{
    let commitments_str = CString::new(commitments).unwrap();
    let share_commit_str = CString::new(share_commit).unwrap();
    let index_str = CString::new(index).unwrap();
    let delta_str =  CString::new(delta).unwrap();
    unsafe{
        return c_char_decode(verify_share_commit_cpp(commitments_str.as_ptr(), share_commit_str.as_ptr(), index_str.as_ptr(), delta_str.as_ptr()));
    }
}

pub fn get_qfi_zero() -> String{
    unsafe{
        return c_char_decode(get_qfi_zero_cpp());
    }
}

pub fn decrypt_c1(cipher: String, sk: String, delta: String) -> String{
    let cipher_str = CString::new(cipher).unwrap();
    let sk_str = CString::new(sk).unwrap();
    let delta_str =  CString::new(delta).unwrap();
    unsafe{
        return c_char_decode(decrypt_c1_cpp(cipher_str.as_ptr(), sk_str.as_ptr(), delta_str.as_ptr()));
    }
}

pub fn multi_decrypt(c1: String, cipher: String, delta: String) -> String{
    let c1_str = CString::new(c1).unwrap();
    let cipher_str = CString::new(cipher).unwrap();
    let delta_str =  CString::new(delta).unwrap();
    unsafe{
        return c_char_decode(multi_decrypt_cpp(c1_str.as_ptr(),cipher_str.as_ptr(), delta_str.as_ptr()));
    }
}

pub fn pre_calculate_pk(pk: String) -> String{
    let pk_str =  CString::new(pk).unwrap();
    unsafe{
        return c_char_decode(pre_calculate_pk_cpp(pk_str.as_ptr()));
    }
}

pub fn to_hex(data : impl AsRef<[u8]>) -> String {
    let data = data.as_ref();
    let len = data.len();
    let mut res = String::with_capacity(len * 2);

    for i in 0..len {
        res.push(HEX_TABLE[usize::from(data[i] >> 4)] );
        res.push(HEX_TABLE[usize::from(data[i] & 0x0F)]);
    }
    res
}
