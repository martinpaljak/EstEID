package org.esteid;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class IDCode {
	private final String countryCode;
	private final String code;


	public IDCode (String country, String code) {
		countryCode = country;
		this.code = code;
	}

	public String getCountryCode() {
		return countryCode;
	}

	public String getCode() {
		return code;
	}

	public static final String REGEXP = "[1-6][0-9]{2}[0,1][0-9][0,1,2,3][0-9]{5}";

	// Given the multipliers, calculate sum
	private static int multsum(int[] mult, int[] src) {
		int sum = 0;
		for(int i = 0; i<10; i++) {
			sum += mult[i]*src[i];
		}
		return sum;
	}

	// Validate an Estonian ID-code
	public static boolean check(String code) {
		if (!code.matches(REGEXP))
			return false;
		int[] original = new int[code.length()];
		for (int i = 0; i < code.length(); i++) {
			original[i] = code.charAt(i) - '0';
		}
		int[] first = {1,2,3,4,5,6,7,8,9,1};
		int[] second = {3,4,5,6,7,8,9,1,2,3};
		// First round
		int csum = multsum(first, original) % 11;
		if (csum == 10) {
			csum = multsum(second, original) % 11;
			// Second round
			if (csum == 10) {
				csum = 0;
			}
		}
		// check
		if (csum == original[original.length - 1]) {
			return true;
		}
		return false;
	}

	public static List<String> extract(String s) {
		List<String> result = new ArrayList<>();
		Pattern p = Pattern.compile(REGEXP);
		Matcher m = p.matcher(s);
		while (m.find()) {
			String c = m.group();
			if (check(c)) {
				result.add(c);
			}
		}
		return result;
	}

	public static void main(String[] args) {
		for (String s: extract("See keegi on 38207162722 ja lisaks 38207162766 ja bööh")) {
			System.out.println(s);
		}
	}
}
