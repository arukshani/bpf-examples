#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#define ELEM(mtx, row, col) \
  mtx->data[(col-1) * mtx->rows + (row-1)]

typedef struct {
  int rows;
//   __u32 rows;
  int cols;
  int * data;
} route_matrix;

typedef struct {
  int rows;
//   __u32 rows;
  int cols;
  struct mac_addr * data;
  // unsigned char * data[ETH_ALEN+1];
} mac_matrix;

struct mac_addr {
   unsigned char bytes[ETH_ALEN+1];
};

/* Sets the (row, col) element of mtx to val.  Returns 0 if
 * successful, -1 if mtx is NULL, and -2 if row or col are
 * outside of the dimensions of mtx.
 */
int setRouteElement(route_matrix * mtx, int row, int col, int val) 
{
  if (!mtx) return -1;
  assert (mtx->data);
  if (row <= 0 || row > mtx->rows ||
      col <= 0 || col > mtx->cols)
    return -2;

  ELEM(mtx, row, col) = val;
  return 0;
}

/* Sets the reference val to the value of the (row, col) 
 * element of mtx.  Returns 0 if successful, -1 if either 
 * mtx or val is NULL, and -2 if row or col are outside of 
 * the dimensions of mtx.
 */
int getRouteElement(route_matrix * mtx, int row, int col, 
               int * val) {
  if (!mtx || !val) return -1;
  assert (mtx->data);
  if (row <= 0 || row > mtx->rows ||
      col <= 0 || col > mtx->cols)
    return -2;

  *val = ELEM(mtx, row, col);
  return 0;
}

/* Creates a ``rows by cols'' matrix with all values 0.  
 * Returns NULL if rows <= 0 or cols <= 0 and otherwise a
 * pointer to the new matrix.
 */
route_matrix * newRouteMatrix(int rows, int cols) {
  if (rows <= 0 || cols <= 0) return NULL;

  // allocate a matrix structure
  route_matrix * m = (route_matrix *) malloc(sizeof(route_matrix));

  // set dimensions
  m->rows = rows;
  m->cols = cols;

  // allocate a double array of length rows * cols
  m->data = (int *) malloc(rows*cols*sizeof(int));
  // set all data to 0
  // int i;
  // for (i = 0; i < rows*cols; i++)
  //   m->data[i] = 0;

  return m;
}

/* Deletes a matrix.  Returns 0 if successful and -1 if mtx 
 * is NULL.
 */
int deleteRouteMatrix(route_matrix * mtx) {
  if (!mtx) return -1;
  // free mtx's data
  assert (mtx->data);
  free(mtx->data);
  // free mtx itself
  free(mtx);
  return 0;
}

////++++++++++++++++++++++++++++++++++++++++++++MAC MATRIX ++++++++++++++++
/* Sets the (row, col) element of mtx to val.  Returns 0 if
 * successful, -1 if mtx is NULL, and -2 if row or col are
 * outside of the dimensions of mtx.
 */
int setMacElement(mac_matrix * mtx, int row, int col, struct mac_addr val) 
{
  if (!mtx) return -1;
  assert (mtx->data);
  if (row <= 0 || row > mtx->rows ||
      col <= 0 || col > mtx->cols)
    return -2;

  ELEM(mtx, row, col) = val;
  return 0;
}

/* Sets the reference val to the value of the (row, col) 
 * element of mtx.  Returns 0 if successful, -1 if either 
 * mtx or val is NULL, and -2 if row or col are outside of 
 * the dimensions of mtx.
 */
int getMacElement(mac_matrix * mtx, int row, int col, 
               struct mac_addr * val) {
  if (!mtx || !val) return -1;
  assert (mtx->data);
  if (row <= 0 || row > mtx->rows ||
      col <= 0 || col > mtx->cols)
    return -2;

  *val = ELEM(mtx, row, col);
  return 0;
}

/* Creates a ``rows by cols'' matrix with all values 0.  
 * Returns NULL if rows <= 0 or cols <= 0 and otherwise a
 * pointer to the new matrix.
 */
mac_matrix * newMacMatrix(int rows, int cols) {
  if (rows <= 0 || cols <= 0) return NULL;

  // allocate a matrix structure
  mac_matrix * m = (mac_matrix *) malloc(sizeof(mac_matrix));

  // set dimensions
  m->rows = rows;
  m->cols = cols;

  // allocate a double array of length rows * cols
  m->data = (struct mac_addr *) malloc(rows*cols*sizeof(struct mac_addr));
  // set all data to 0
  // int i;
  // for (i = 0; i < rows*cols; i++)
  //   m->data[i] = 0;

  return m;
}

/* Deletes a matrix.  Returns 0 if successful and -1 if mtx 
 * is NULL.
 */
int deleteMacMatrix(mac_matrix * mtx) {
  if (!mtx) return -1;
  // free mtx's data
  assert (mtx->data);
  free(mtx->data);
  // free mtx itself
  free(mtx);
  return 0;
}

route_matrix * A;
mac_matrix * B;

//++++++++++++++++++++++++++++++HASHTABLE IMPLEMENTATION+++++++++++++++++++++++++++++++++++++++++++++++++++++
struct HashNode {
	int key;
	int value;
};

const int capacity = 20;
int size = 0;

struct HashNode** arr;
struct HashNode* dummy;

// Function to add key value pair
void insert(int key, int V)
{

	struct HashNode* temp
		= (struct HashNode*)malloc(sizeof(struct HashNode));
	temp->key = key;
	temp->value = V;

	// Apply hash function to find
	// index for given key
	int hashIndex = key % capacity;

	// Find next free space
	while (arr[hashIndex] != NULL
		&& arr[hashIndex]->key != key
		&& arr[hashIndex]->key != -1) {
		hashIndex++;
		hashIndex %= capacity;
	}

	// If new node to be inserted
	// increase the current size
	if (arr[hashIndex] == NULL
		|| arr[hashIndex]->key == -1)
		size++;

	arr[hashIndex] = temp;
}

// Function to delete a key value pair
int delete (int key)
{
	// Apply hash function to find
	// index for given key
	int hashIndex = key % capacity;

	// Finding the node with given
	// key
	while (arr[hashIndex] != NULL) {
		// if node found
		if (arr[hashIndex]->key == key) {
			// Insert dummy node here
			// for further use
			arr[hashIndex] = dummy;

			// Reduce size
			size--;

			// Return the value of the key
			return 1;
		}
		hashIndex++;
		hashIndex %= capacity;
	}

	// If not found return null
	return 0;
}

// Function to search the value
// for a given key
int find(int key)
{
	// Apply hash function to find
	// index for given key
	int hashIndex = (key % capacity);

	int counter = 0;

	// Find the node with given key
	while (arr[hashIndex] != NULL) {

		int counter = 0;
		// If counter is greater than
		// capacity
		if (counter++ > capacity)
			break;

		// If node found return its
		// value
		if (arr[hashIndex]->key == key)
			return arr[hashIndex]->value;

		hashIndex++;
		hashIndex %= capacity;
	}

	// If not found return
	// -1
	return -1;
}

//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++