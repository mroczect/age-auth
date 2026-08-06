use libage_auth_handler::Algo;

#[test]
fn test_algo_default() {
    assert_eq!(Algo::DEFAULT, Algo::Sha256);
}
