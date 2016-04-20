package org.esteid;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class IDCode {

	// Given the multipliers, calculate sum
	private static int multsum(int[] mult, int[] src) {
		int sum = 0;
		for(int i = 0; i<10; i++) {
			sum += mult[i]*src[i];
		}
		return sum;
	}

	// Validate an Estonian ID-code
	public static boolean is_valid_idcode(String code) {
		if (!code.matches("\\d{11}"))
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

	public static String extract_idcode(String s) {
		Pattern p = Pattern.compile("\\d{11}");
		Matcher m = p.matcher(s);
		while (m.find()) {
			String c = m.group();
			if (is_valid_idcode(c)) {
				return c;
			}
		}
		return null;
	}
}
