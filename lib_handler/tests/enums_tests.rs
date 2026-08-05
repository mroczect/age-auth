use lib_handler::Algo;

#[test]
fn test_algo_default() {
    assert_eq!(Algo::DEFAULT, Algo::Sha1);
}
