
// typedefs for queue
typedef struct Node
{
  void *data;
  struct Node *next;
}node;

typedef struct QueueList
{
    int sizeOfQueue;
    size_t memSize;
    node *head;
    node *tail;
}Queue;


// Queue declaration
void queueInit(Queue *q, size_t memSize)
{
   q->sizeOfQueue = 0;
   q->memSize = memSize;
   q->head = q->tail = NULL;
}

int queue_try_put(Queue *q, const void *data)
{
    node *newNode = (node *)malloc(sizeof(node));
    if(newNode == NULL){
    	return -1;
    }
    newNode->data = malloc(q->memSize);
    if(newNode->data == NULL){
        free(newNode);
        return -1;
    }
    newNode->next = NULL;
    memcpy(newNode->data, data, q->memSize);
    if(q->sizeOfQueue == 0){
        q->head = q->tail = newNode;
    }
    else{
        q->tail->next = newNode;
        q->tail = newNode;
    }
    q->sizeOfQueue++;
    return 0;
}

void* queue_try_get(Queue *q)
{
    void *data = NULL;
    if(q->sizeOfQueue > 0)
    {
        node *temp = q->head;
        memcpy(data, temp->data, q->memSize);
        if(q->sizeOfQueue > 1){
            q->head = q->head->next;
        }
        else{
            q->head = NULL;
            q->tail = NULL;
        }
        q->sizeOfQueue--;
        free(temp->data);
        free(temp);
    }
    return data;
}
