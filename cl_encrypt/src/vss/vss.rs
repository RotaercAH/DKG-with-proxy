use crate::cl::clwarpper::{power_of_h, verify_share, calculate_commitments, verify_share_commit};
/*
    This file is part of OpenTSS.
    Copyright (C) 2022 LatticeX Foundation.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
use crate::{CU, FE, GE};
use curv::elliptic::curves::{Secp256k1, Curve, Point, Scalar};
use curv::arithmetic::{Converter, Samplable};
use curv::arithmetic::One;
//use curv::cryptographic_primitives::commitments;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::ShamirSecretSharing;
use curv::cryptographic_primitives::secret_sharing::Polynomial;
use curv::BigInt;
use curv::ErrorSS;
use curv::ErrorSS::VerifyShareError;
use std::time::Instant;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Vss {
    pub parameters: ShamirSecretSharing,
    pub commitments: Vec<GE>,
}
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct IntegerVss {
    pub parameters: ShamirSecretSharing,
    pub commitments: Vec<String>,
}

impl Vss {
    pub fn validate_share(&self, secret_share: &FE, index: String) -> Result<(), ErrorSS> {
        let ss_point = Point::generator() * secret_share;
        self.validate_share_public(&ss_point, index)
    }

    pub fn validate_share_public(&self, ss_point: &GE, index: String) -> Result<(), ErrorSS> {
        let comm_to_point = self.get_point_commitment(index);
        if *ss_point == comm_to_point {
            Ok(())
        } else {
            Err(VerifyShareError)
        }
    }

    pub fn get_point_commitment(&self, index: String) -> GE {
        let index_fe: FE = Scalar::from(&BigInt::from_str_radix(&index, 16).unwrap());
        let mut comm_iterator = self.commitments.iter().rev();
        let head = comm_iterator.next().unwrap();
        let tail = comm_iterator;
        tail.fold(head.clone(), |acc, x: &GE| x + acc * &index_fe)
    }
}

impl IntegerVss {
    pub fn validate_share(&self, secret_share: &BigInt, index: String, delta: &BigInt) -> Result<(), ErrorSS> {
        let commitments =  self.commitments.join(":");
        let res = verify_share(commitments, secret_share.to_string(), index, delta.to_string());
        println!("res: {}", res);
        if res == "true" {
            Ok(())
        } else {
            Err(VerifyShareError)
        }
    }
    pub fn verify_point_commitment(&self, index: String, share_commit: String, delta: &BigInt) -> String{
        let commitments =  self.commitments.join(":");
        return verify_share_commit(commitments, share_commit, index, delta.to_string());
    }
}


pub fn integer_share_at_indices(  
    t: u16,
    n: u16,
    secret: BigInt,
    coefficients_bound :BigInt,
) -> (IntegerVss, Vec<BigInt>) {
    let mut coefficients : Vec<BigInt> =  (0..t).map(|_| {
            let random_bigint = BigInt::sample_below(&coefficients_bound);
            random_bigint
        }).collect();

    let mut delta = BigInt::one();
    for i in 1..=n{
        delta *= BigInt::from(i);
    }
    
    coefficients[0] = secret.clone() * delta.clone();

    let secret_shares = evaluate_polynomial_integer(coefficients.clone(), n);
    
    let coefficients_strings: Vec<String> = coefficients.iter().map(|bigint| bigint.to_string()).collect();
    let coefficients_string =  coefficients_strings.join(":");
    let commitments_string = calculate_commitments(coefficients_string, delta.to_string());
    let mut commitments : Vec<String> = commitments_string.split(':').map(String::from).collect();
    // let mut commitments = (0..coefficients.len()).map(|i| calculate_commit(coefficients[i].to_string(), delta.to_string())).collect::<Vec<String>>();
    // commitments[0] = power_of_h(secret.to_string());
    commitments[0] = power_of_h(secret.to_string());
    (
        IntegerVss {
            parameters: ShamirSecretSharing {
                threshold: t as u16,
                share_count: n as u16,
            },
            commitments,
        },
        secret_shares,
    )
}

pub fn share_at_indices(
    t: usize,
    n: usize,
    secret: &FE,
    index_vec: &Vec<String>,
) -> (Vss, HashMap<String, FE>) {
    assert_eq!(n, index_vec.len());
    let poly = Polynomial::<CU>::sample_exact_with_fixed_const_term(t as u16, secret.clone());
    let secret_shares = evaluate_polynomial(&poly, &index_vec);
    let g = Point::generator();
    let poly = poly.coefficients();
    let commitments = (0..poly.len()).map(|i| g * &poly[i]).collect::<Vec<GE>>();
    (
        Vss {
            parameters: ShamirSecretSharing {
                threshold: t as u16,
                share_count: n as u16,
            },
            commitments,
        },
        secret_shares,
    )
}

fn evaluate_polynomial(poly: &Polynomial<CU>, index_vec_string: &[String]) -> HashMap<String, FE> {
    let mut share_map: HashMap<String, FE> = HashMap::new();
    for i in index_vec_string {
        let value = poly.evaluate(&Scalar::from(&BigInt::from_str_radix(&i, 16).unwrap()));
        share_map.insert((*i).clone(), value);
    }
    return share_map;
}

fn evaluate_polynomial_integer(coefficients: Vec<BigInt>, n: u16) -> Vec<BigInt> {
    let mut share_map: Vec<BigInt> = Vec::new();
    for i in 1..=n {
        let value = evaluate(coefficients.clone(), BigInt::from(i));
        share_map.push(value);
    }
    return share_map;
}

fn evaluate(coefficients: Vec<BigInt>, x: BigInt) -> BigInt{
    let mut result = BigInt::from(0);
    let mut power_of_x = BigInt::one();

    for coefficient in coefficients {
        result += &power_of_x * &coefficient;
        power_of_x *= &x;
    }

    result
}

pub fn integer_map_share_to_new_params(index: BigInt, s: &[BigInt], n: usize) -> BigInt {
    let s_len = s.len();
    // add one to indices to get points

    let xi = index.clone();
    let num = BigInt::one();
    let denum: BigInt = BigInt::one();
    let mut delta = BigInt::one();
    let num = (0..s_len).fold(
        num,
        |acc, i| {
            if s[i] != index {
                acc * &s[i]
            } else {
                acc
            }
        },
    );
    
    let denum = (0..s_len).fold(denum, |acc, i| {
        if s[i] != index {
            let xj_sub_xi = &s[i] - &xi;
            acc * xj_sub_xi
        } else {
            acc
        }
    });

    for i in 1..=n as u16 {
        delta *= BigInt::from(i);
    }

    // let denum = denum.invert().unwrap();
    num * delta / denum
}

pub fn map_share_to_new_params(index: BigInt, s: &[BigInt]) -> FE {
    let s_len = s.len();
    // add one to indices to get points
    let points: Vec<FE> = s.iter().map(|i| Scalar::from(i)).collect();

    let xi: FE = Scalar::from(&index);
    let num: FE = Scalar::from(&BigInt::one());
    let denum: FE = Scalar::from(&BigInt::one());
    let num = (0..s_len).fold(
        num,
        |acc, i| {
            if s[i] != index {
                acc * &points[i]
            } else {
                acc
            }
        },
    );
    let denum = (0..s_len).fold(denum, |acc, i| {
        if s[i] != index {
            let xj_sub_xi = &points[i] - &xi;
            acc * xj_sub_xi
        } else {
            acc
        }
    });
    let denum = denum.invert().unwrap();
    num * denum
}

#[test]
fn test_select_polynomial_time() {
    for i in 0..= 50{
        let t:usize = i * 10;
        let n:usize = 2 * t + 1;
        let fe: FE = Scalar::from(&BigInt::from_str_radix("123", 16).unwrap());
        let mut index_vec = Vec::new();
        for i in 1..= n{
            index_vec.push(format!("{}", i));
        }
        let (_vss_scheme, shares) = share_at_indices(t, n, &fe, &index_vec);
    }
}

#[test]
fn test_vss() {
    use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
    let fe: FE = Scalar::from(&BigInt::from_str_radix("123", 16).unwrap());
    let point1 = BigInt::from_str_radix("111", 16).unwrap();
    let point2 = BigInt::from_str_radix("222", 16).unwrap();
    let point3 = BigInt::from_str_radix("333", 16).unwrap();

    let index_vec = vec!["111".to_string(), "222".to_string(), "333".to_string()];
    let (_vss_scheme, shares) = share_at_indices(1, 3, &fe, &index_vec);

    let vec_reconstruct = vec![point1, point2, point3];
    let mut points = Vec::<FE>::new();
    for i in vec_reconstruct.iter() {
        points.push(FE::from_bigint(&i));
    }

    let mut shares1: Vec<FE> = Vec::new();
    shares1.push(shares.get(&"111".to_string()).unwrap().clone());
    shares1.push(shares.get(&"222".to_string()).unwrap().clone());
    shares1.push(shares.get(&"333".to_string()).unwrap().clone());

    let result = VerifiableSS::<CU>::lagrange_interpolation_at_zero(&points, &shares1);
    assert_eq!(fe, result);
}

#[test]
fn test_vss_run_time() {
    let fe: FE = Scalar::from(&BigInt::from_str_radix("72048742277494395339533061984139355904610663484117275638395963297495883454538", 10).unwrap());
    let bound = BigInt::from_str_radix("519825222697581994973081647134787959795934971297792", 10).unwrap();
    let secret = BigInt::from_str_radix("2044", 16).unwrap();
    let mut delta = BigInt::one();
    let t = 30;
    let n = 100;
    for i in 1..=n{
        delta *= BigInt::from(i);
    }
    let mut index_vec = Vec::new();
    for i in 1..=n {
        index_vec.push(i.to_string());
    }
    
    let (_vss_scheme, shares) = integer_share_at_indices(t, n, secret.clone(), bound.clone());
    let (_vss_scheme_ecc, shares_ecc) = share_at_indices(t as usize, n as usize, &fe, &index_vec);
    
    let mut start = Instant::now();
    for i in 1..10{
        let (_vss_scheme, shares) = integer_share_at_indices(t, n,  secret.clone(), bound.clone());
    }
    let mut end = Instant::now();
    println!("多项式生成10次运行时间(CL): {:?}", end - start);

    start = Instant::now();
    for i in 1..10{
        let (_vss_scheme, shares) = share_at_indices(t as usize, n as usize,  &fe, &index_vec);
    }
    end = Instant::now();
    println!("多项式生成10次运行时间(ECC): {:?}", end - start);

    start = Instant::now();
    for i in 1..10{
        _vss_scheme.validate_share(&shares[2], "3".to_string(), &delta);
    }
    end = Instant::now();
    println!("点值验证10次运行时间(CL): {:?}", end - start);

    start = Instant::now();
    for i in 1..10{
        _vss_scheme_ecc.validate_share(&shares_ecc.get(&"3".to_string()).unwrap().clone(), "3".to_string());
    }
    end = Instant::now();
    println!("点值验证10次运行时间(ECC): {:?}", end - start);
}

#[test]
fn test_integer_vss_2_out_of_4() {
    let bound = BigInt::from_str_radix("519825222697581994973081647134787959795934971297792", 10).unwrap();
    let secret = BigInt::from_str_radix("2044", 10).unwrap();
    let mut delta = BigInt::one();
    for i in 1..=100 as u16 {
        delta *= BigInt::from(i);
    }
    println!("delta * share: {:?} ", delta * 2044);
    let mut index_vec = Vec::new();
    for i in 1..=4 as u16 {
        index_vec.push(i.to_string());
    }
    let (_vss_scheme, shares) = integer_share_at_indices(30, 100, secret.clone(), bound);
    println!("vss_share: {:?} ", shares);
    // println!("commitment0: {:?} ", _vss_scheme.commitments.get(0));
    // let lagrange_vec = vec![BigInt::from_str_radix("1", 16).unwrap(), BigInt::from_str_radix("2", 16).unwrap(), BigInt::from_str_radix("3", 16).unwrap()];
    // let l1 = integer_map_share_to_new_params(BigInt::from_str_radix("1", 10).unwrap(), &lagrange_vec, 4);
    // println!("l1 : {:?}", l1);
    // let l2 = integer_map_share_to_new_params(BigInt::from_str_radix("2", 10).unwrap(), &lagrange_vec, 4);
    // println!("l2 : {:?}", l2);
    // let l3 = integer_map_share_to_new_params(BigInt::from_str_radix("3", 10).unwrap(), &lagrange_vec, 4);
    // println!("l3 : {:?}", l3);
    // let w = l1 * shares.get(0).unwrap() + l2 * shares.get(1).unwrap()  + l3 * shares.get(2).unwrap();
    // println!("w : {:?}", w);
    // let s_delta = secret * delta.clone() * delta.clone();
    // println!("s_delta : {:?}", s_delta);
}

#[test]
fn test_vss_1_out_of_3() {
    use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
    let fe: FE = Scalar::from(&BigInt::from_str_radix("72048742277494395339533061984139355904610663484117275638395963297495883454538", 10).unwrap());
    let point1 = BigInt::from_str_radix("11", 16).unwrap();
    let point2 = BigInt::from_str_radix("22", 16).unwrap();
    let point3 = BigInt::from_str_radix("33", 16).unwrap();
    // let g = Point::generator();

    let index_vec = vec!["11".to_string(), "22".to_string(), "33".to_string()];
    let (_vss_scheme, shares) = share_at_indices(1, 3, &fe, &index_vec);

    let vec_reconstruct = vec![point1, point2, point3];
    let mut points = Vec::<FE>::new();
    for i in vec_reconstruct.iter() {
        points.push(FE::from_bigint(&i));
    }

    let mut shares1: Vec<FE> = Vec::new();
    shares1.push(shares.get(&"11".to_string()).unwrap().clone());
    shares1.push(shares.get(&"22".to_string()).unwrap().clone());
    shares1.push(shares.get(&"33".to_string()).unwrap().clone());
    
    // let valid11 = pedersen_validate_share(&_vss_scheme, 
    // &pedersen_secret_shares.secret_shares.get(&"11".to_string()).unwrap().clone(), 
    // &pedersen_secret_shares.pedersen_random.get(&"11".to_string()).unwrap().clone(), "11".to_string());
    // assert!(valid11.is_ok());

    let lagrange_vec = vec![BigInt::from_str_radix("11", 16).unwrap(), BigInt::from_str_radix("22", 16).unwrap()];
    let l11 = map_share_to_new_params(BigInt::from_str_radix("11", 16).unwrap(), &lagrange_vec);
    println!("s11 is {}", l11.to_bigint());
    println!("l11 is {}", shares.get(&"11".to_string()).unwrap().to_bigint());
    let l22 = map_share_to_new_params(BigInt::from_str_radix("22", 16).unwrap(), &lagrange_vec);
    println!("s22 is {}", l22.to_bigint());
    println!("l22 is {}", shares.get(&"22".to_string()).unwrap().to_bigint());
    let w = l11 * shares.get(&"11".to_string()).unwrap().clone()+ l22 * shares.get(&"22".to_string()).unwrap().clone();
    assert_eq!(fe, w);
    println!("w is {}", w.to_bigint());
    // let result = VerifiableSS::<CU>::lagrange_interpolation_at_zero(&points, &shares1);
    // println!("fe is {}", fe.to_bigint());
    // println!("result is {}", result.to_bigint());
    // assert_eq!(fe, result);
}

#[test]
fn test_pedersen_vss_1_out_of_3() {
    use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
    // let fe: FE = Scalar::from(&BigInt::from_str_radix("1444444", 16).unwrap());
    let point1 = BigInt::from_str_radix("11", 16).unwrap();
    let point2 = BigInt::from_str_radix("22", 16).unwrap();
    let point3 = BigInt::from_str_radix("33", 16).unwrap();

    // let index_vec = vec!["11".to_string(), "22".to_string(), "33".to_string(), "44".to_string(), "55".to_string(), "66".to_string(), "77".to_string()];
    // let (_vss_scheme, pedersen_secret_shares) = pedersen_share(3, 7, &fe, &random, &index_vec);

    let vec_reconstruct = vec![point1, point2, point3];
    let mut points = Vec::<FE>::new();
    for i in vec_reconstruct.iter() {
        points.push(FE::from_bigint(&i));
    }

    let mut shares1: Vec<FE> = Vec::new();
    let share_sk3: FE = Scalar::from(&BigInt::from_str_radix("17b35f297e93bd4228f8edf33fbb895dcb43b557edcd04cebc8d2f9c65d720f", 16).unwrap());
    let share_sk2: FE = Scalar::from(&BigInt::from_str_radix("d0ca35d6ef7ae7689ab6c0a9743cd477c5b73a552975416f9f1d098c905bc967", 16).unwrap());
    let share_sk1: FE = Scalar::from(&BigInt::from_str_radix("6922b5e4c3b2119e5ea327c4541c4686d135bad5542908de4572ee432b5c9dbb", 16).unwrap());
    println!("{:#?}", share_sk1.clone());
    shares1.push(share_sk1);
    shares1.push(share_sk2);
    shares1.push(share_sk3);

    let result = VerifiableSS::<CU>::lagrange_interpolation_at_zero(&points, &shares1);
    // println!("fe is {}", fe.to_bigint());
    let base = Point::<Secp256k1>::generator();
    let pk = base * result.clone();
    let pkxy = vec![
        pk.x_coord().unwrap().to_hex(),
        pk.y_coord().unwrap().to_hex()
    ];
    println!("result is {:#?}", result.clone());
    println!("{:#?}", pkxy);
    // assert_eq!(fe, result);
}