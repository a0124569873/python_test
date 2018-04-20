Usage
=====

|fp-qos| provides the following functions:

Initialization
   *fpn_sw_sched_allocate* is used to create a port scheduler and returns an
   opaque pointer that is used by other functions.
Classifying packets
   *fpn_sw_sched_classify* is used to classify packets.
Enqueuing packets
   *fpn_sw_sched_enqueue* stores packets in the queue corresponding to the
   packets' class.
Dequeuing packets
   *fpn_sw_sched_dequeue* returns packets waiting in the scheduler, these
   packets can then be processed and sent over the wire.
