#include<sys/un.h>
#include<unistd.h>
#include<stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/queue.h>

struct mbuflist
{
    int data;
	void *p;
    LIST_ENTRY(mbuflist) list;
};
struct listhead *headp;

int main(void)
{
	LIST_HEAD(listhead, mbuflist) head; /* Initialize the list. */
	struct mbuflist *n1, *n2, *np;

	LIST_INIT(&head);
	n1 = malloc(sizeof(struct mbuflist));      /* Insert at the head. */
	n1->data = 1;
	LIST_INSERT_HEAD(&head, n1, list);

	n2 = malloc(sizeof(struct mbuflist));      /* Insert at the head. */
	n2->data = 2;
	LIST_INSERT_HEAD(&head, n2, list);
										 /* Forward traversal. */
	LIST_FOREACH(np, &head, list) {
		 printf("got data %d\n", np->data);
	}

	 while(!LIST_EMPTY(&head)){
        np = LIST_FIRST(&head);
        printf("remove %d\n", np->data);
        LIST_REMOVE(np, list);
        free(np);
    }

	return 0;
}
