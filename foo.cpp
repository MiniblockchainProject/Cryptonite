#include <boost/test/unit_test.hpp>

using boost::unit_test::test_suite;

int main(){
	test_suite* test= BOOST_TEST_SUITE( "Unit test example 1" ); 
	return 0;
}
