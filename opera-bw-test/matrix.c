#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  int rows;
  int cols;
  double * data;
} matrix;

/* Creates a ``rows by cols'' matrix with all values 0.  
 * Returns NULL if rows <= 0 or cols <= 0 and otherwise a
 * pointer to the new matrix.
 */
matrix * newMatrix(int rows, int cols) {
  if (rows <= 0 || cols <= 0) return NULL;

  // allocate a matrix structure
  matrix * m = (matrix *) malloc(sizeof(matrix));

  // set dimensions
  m->rows = rows;
  m->cols = cols;

//   allocate a double array of length rows * cols
  m->data = (double *) malloc(rows*cols*sizeof(double));
  // set all data to 0
  int i;
  for (i = 0; i < rows*cols; i++)
    m->data[i] = 0.0;

  return m;
}

int main() {
    matrix * A;
    A = newMatrix(3, 3);
}