#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct Matrix {
    int rows; // number of rows
    int cols; // number of columns
    double** data; // a pointer to an array of n_rows pointers to rows; a row is an array of n_cols doubles 
};
typedef struct Matrix Matrix;

Matrix* make_matrix(int n_rows, int n_cols) {
    struct Matrix* matrix = malloc(sizeof(Matrix));
    matrix->rows = n_rows;
    matrix->cols = n_cols;
    double** data = malloc(sizeof(double*) * n_rows); 
    for(int x = 0; x < n_rows; x++){
        data[x] = calloc(n_cols, sizeof(double));
    }
    matrix->data = data;
    return matrix;
}

Matrix* copy_matrix(double* data, int n_rows, int n_cols) {
    struct Matrix *matrix = make_matrix(n_rows, n_cols);
    for(int x = 0; x < n_rows; x++) {
        for(int y = 0; y < n_cols; y++) {
            matrix->data[x][y] = data[n_cols*x+y];
        }
    }
    return matrix;    
}

void print_matrix(Matrix* m) {
    for(int x = 0; x < m->rows; x++) {
        printf("%s", "\n");
        for(int y = 0; y < m->cols; y++) {
            printf("%f\t", m->data[x][y]);
        }
    }
}

void matrix_test(void) {   

    double a[] = { 
        1, 2, 3, 
        4, 5, 6, 
        7, 8, 9,
        10,11,12
        };
    Matrix* m1 = copy_matrix(a, 4, 3);
    print_matrix(m1);
}

int main(void) {
    base_init();
    base_set_memory_check(free);
    matrix_test();
    return 0;
}