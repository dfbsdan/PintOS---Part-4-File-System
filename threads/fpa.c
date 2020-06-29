#include "threads/fpa.h"
#include <stdio.h>

/* Integer to fixed point */
int n_to_fp (int n) {
  return n * F;
}

/* Fixed point to integer, rounded to nearest */
int fp_to_n_near (int x) {
  return x / F;
}

/* Fixed point to integer, rounded down */
int fp_to_n_down (int x) {
  return (x >= 0)? (x + F / 2) / F:
      (x - F / 2) / F;
}

/* Add fp and fp */
int add_fp (int x, int y) {
  return x + y;
}

/* Subtract fp and fp */
int sub_fp (int x, int y) {
  return x - y;
}

/* Add fp and int */
int add_fp_n (int x, int n) {
  return x + n * F;
}

/* Subtract fp and int */
int sub_fp_n (int x, int n) {
  return x - n * F;
}

/* Multiply fp and fp */
int mult_fp (int x, int y) {
  return ((int64_t) x) * y / F;
}

/* Multiply fp and int */
int mult_fp_n (int x, int n) {
  return x * n;
}

/* Divide fp and fp */
int div_fp (int x, int y) {
  return ((int64_t) x) * F / y;
}

/* Divide fp and int */
int div_fp_n (int x, int n) {
  return x / n;
}
