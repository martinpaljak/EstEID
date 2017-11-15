/**
 * Copyright (c) 2014-2017 Martin Paljak
 * <p>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p>
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.esteid;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class IDCode {
    public static final String REGEXP = "[1-6][0-9]{2}[0,1][0-9][0,1,2,3][0-9]{5}";

    // Given the multipliers, calculate sum
    private static int multsum(int[] mult, int[] src) {
        int sum = 0;
        for (int i = 0; i < 10; i++) {
            sum += mult[i] * src[i];
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
        int[] first = {1, 2, 3, 4, 5, 6, 7, 8, 9, 1};
        int[] second = {3, 4, 5, 6, 7, 8, 9, 1, 2, 3};
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
}
