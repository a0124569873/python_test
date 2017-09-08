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
void sortNode(PNode head,int length) {
	PNode p = NULL,q = NULL,temp = NULL,subHead = NULL;
	int i,j;
	length--;
	length--;
	for(i = 0;i < length;i++){
		subHead = head;
		p = head ->next;
		q = p ->next;
		for(j = 0;j < (length-i);j++){
			if(p->id>q->id){
				subHead->next = p->next;
				p->next = q->next;
				q->next = p;
				temp = p;
				p = q;
				q = temp;
			}
			subHead = subHead->next;
			p = p->next;
			q = q->next;
		}
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
	insertNode(p, 2);
	insertNode(p, 1);
	int s = getSize(p);
	sortNode(p,s);
	printNode(p);



}





