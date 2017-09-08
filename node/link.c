#include <stdio.h>
#include <stdlib.h>

typedef int BOOL;
#define true 0
#define false 1

typedef struct Node *PNode;

//define node
typedef struct Node {
	int id;
	PNode pre;
	PNode next;
} Node;
//createnode
PNode makeNode(int id) {
	PNode p = NULL;
	p = (PNode) malloc(sizeof(Node));
	if (p != NULL) {
		p->id = id;
		p->pre = NULL;
		p->next = NULL;
	}
	return p;
}

//insert node
PNode insertNode(PNode p, int id) {
	PNode np = NULL;
	np = (PNode) malloc(sizeof(Node));

	np->id = id;

	np->pre = p;
	np->next = p->next;
	if (p->next) {
		p->next->pre = np;
	}
	p->next = np;
	return p;

}

void sort_node(PNode head) {
	PNode p1,p2;
	p1 = head;
	p2 = head;
	while(p1->next){
		p2 = p1;
		while(p2->next){
			PNode tmp = p2->next;
			if(!tmp){
				continue;
			}
			if(tmp->id<p2->id){
				p2->pre->next = tmp;
				tmp->next->pre = p2;

				p2->next = tmp->next;
				tmp->pre = p2->pre;

				p2->pre = tmp;
				tmp->next = p2;

//				p2 = tmp;
			}
			p2 = p2->next;
		}
		p1 = p1->next;
	}
}

int getSize(PNode p) {
	PNode np = NULL;
	np = p;
	int i = 0;
	//get node length
	while (np != NULL) {
		i++;
		np = np->next;
	}
	printf("size:%d\n", i);
}

//print node
void printNode(PNode p) {
	PNode np = NULL;
	np = p;
	while (np != 0) {
		printf("%p %d\n", np, np->id);
		np = np->next;

	}
}




int main (){
	PNode p = makeNode(0);
	insertNode(p, 4);
	insertNode(p, 3);
//	insertNode(p, 1);
//	insertNode(p, 2);
//	insertNode(p, 8);
//	insertNode(p, 5);
//	insertNode(p, 7);
//



	int s = getSize(p);
	sort_node(p);
	printNode(p);



}


