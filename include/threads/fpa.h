#define F (1 << 14) //Fixed point 1
#define INT_MAX ((1 << 31) - 1)
#define INT_MIN (-(1 << 31))

/* X and Y denote fixed_point numbers in 17.14 format
   N is an integer. */
int n_to_fp (int n);
int fp_to_n_near (int x);
int fp_to_n_down (int x);
int add_fp (int x, int y);
int sub_fp (int x, int y);
int add_fp_n (int x, int n);
int sub_fp_n (int x, int n);
int mult_fp (int x, int y);
int div_fp (int x, int y);
int mult_fp_n (int x, int n);
int div_fp_n (int x, int n);
