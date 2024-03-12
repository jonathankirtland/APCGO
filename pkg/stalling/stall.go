package stalling

// isPrime checks if a number is prime
func isPrime(n int) bool {
	if n <= 1 {
		return false
	}
	for i := 2; i*i <= n; i++ {
		if n%i == 0 {
			return false
		}
	}
	return true
}

// calculatePrimes finds all prime numbers up to a certain limit
func CalculatePrimes(limit int) {
	for num := 1; num <= limit; num++ {
		if isPrime(num) {
			// Uncomment the following line to see the primes as they are found
			// fmt.Println(num)
		}
	}
}
