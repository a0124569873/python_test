mbuf structure API
==================

Abstract: packet descriptor, segment descriptor
-----------------------------------------------

Whatever the architecture, a network packet is represented by the following
structures:

mbuf
   Packet descriptor that contains data common to all packet parts. For
   instance, the private part of the *mbuf* structure (which is
   application-specific) is accessed through the *m_priv(m)* function.
   On some architectures, the *mbuf* structure also embeds the first segment.

sbuf
   One or several segment descriptors, associated with a contiguous memory
   buffer.

Some macros and functions help browse *mbuf* structures and segments. For
instance, *M_FOREACH_SEGMENT(m, s)* browses packet segments.

.. seealso::

   :ref:`M_FOREACH_SEGMENT <m_foreach_segment>`

Implementation examples
-----------------------

The implementation may differ on your architecture. You can map the *mbuf* or
*sbuf* structures to hardware-specific structures.

VFP (emulator)
~~~~~~~~~~~~~~

On the emulator, the *mbuf* and the *sbuf* structures are allocated separately.

.. rubric:: Diagram

.. figure:: images/mbuf_vfp.svg
    :alt: mbuf_vfp

DPDK
~~~~

On |dpdk|, the *mbuf* and the *sbuf* structures are the same. The
*mbuf*/*sbuf* structure is located at the beginning of the packet buffer.

.. rubric:: Diagram

.. figure:: images/mbuf_dpdk.svg
    :alt: mbuf_dpdk

Octeon MCEE
~~~~~~~~~~~

In work queue entries, *wqe.word2.s.bufs* stores the number of segments in a
network packet.

The pointer to buffer *N+1* is stored just before the buffer *N* data.

.. note::

   - The *m_adj()* function overrides adjusted headers.

   - The buffer pointer field in the last buffer contains unpredictable data
     that should not be used by core software.

   - As the number of segments is known, the last next pointer is fixed
     manually (set to NULL) at the reception of the packet. This allows for
     faster segments browsing and for a generic implementation of the
     *M_FOREACH_SEGMENT* macro.

.. rubric:: Diagram

.. figure:: images/mbuf_octeon.svg
    :alt: mbuf_octeon

.. seealso::

   - :ref:`M_FOREACH_SEGMENT <m_foreach_segment>`

   - :ref:`m_adj <m_adj>`

API
---

.. program:: API

.. _m_foreach_segment:

.. option:: M_FOREACH_SEGMENT

   .. rubric:: Description

   Helper to browse each segment in an *mbuf* structure.

   .. rubric:: Syntax

   .. code-block:: c

      M_FOREACH_SEGMENT(struct mbuf *m, struct sbuf *s)

   .. rubric:: Example

   .. code-block:: c

      struct sbuf *s;
      int i=0;
      M_FOREACH_SEGMENT(m, s) {
              fpn_printf("Segment %d: len is %d\n", i, s_len(s));
              i++;
      }

.. _m_adj:

.. option:: m_adj

   .. rubric:: Description

   Remove *len* bytes of data at the beginning of the *mbuf* structure. If *len*
   is higher than the length of the first *segment*, the function fails and
   returns NULL, without modifying the *mbuf* structure.

   .. note::

      - *len* must always be > 0.

      - To remove data at the end of buffer, use the *m_trim()* function.

   .. warning::

      Depending on your architecture, the *m_adj()* function may modify the
      content of *adjusted* data. The following code may modify the data
      referenced by *m*:

      .. code-block:: c

            m_adj(m, len);
            m_prepend(m, len);

   .. rubric:: Syntax

   .. code-block:: c

      char *m_adj(struct mbuf *m, uint32_t len)

   .. rubric:: Diagram

   .. figure:: images/m_adj.svg
       :alt: m_adj

   .. seealso::

      :ref:`m_save_mac / m_restore_mac <m_save_mac_m_restore_mac>`

.. option:: m_adj2

   .. rubric:: Description

   Remove *len* bytes of data at the beginning of the *mbuf* structure. The
   first segment of the resulting *mbuf* structure can be empty. To fill the
   first segment, use the *m_pullup()* function.

   On success
      Return the pointer to the head of data.

   On error
      Return NULL.

   .. rubric:: Syntax

   .. code-block:: c

      char *m_adj2(struct mbuf *m, uint32_t len)

.. option:: m_alloc

   .. rubric:: Description

   Allocate a new *mbuf* structure. Return NULL if allocation failed. The new
   *mbuf* structure contains one segment, whose length is 0. The data pointer is
   initialized to free headroom in the buffer.

   .. rubric:: Syntax

   .. code-block:: c

      struct mbuf *m_alloc(void)

   .. rubric:: Parameters

   None

   .. rubric:: Diagram

   .. figure:: images/m_alloc.png
       :alt: m_alloc

.. option:: m_append

   .. rubric:: Description

   Append space of size *len* to *mbuf* structure. Return a pointer to the start
   address of the added data.

   On some architectures, if there is not enough tailroom in the last
   segment, the function does not allocate a new segment and returns NULL,
   without modifying the *mbuf* structure.

   .. rubric:: Syntax

   .. code-block:: c

      char *m_append(struct mbuf *m, unsigned int len)

   .. rubric:: Diagram

   .. figure:: images/m_append.svg
       :alt: m_append

   .. note::

         This function is often followed by the *memcpy()* function. In this
         case, it may be better to use the *m_copyfrombuf()* function: it
         appends and copies at the same time, allocating a new segment if
         necessary.

.. option:: m_cat

   .. rubric:: Description

   Concatenate *mbuf* structure *m2* to *m1*.

   On success
      Return 0 and free *m2*.

   On error
      Return -1, and do not free *m1* and *m2*.

   The function does not add or remove data, it only links the segments
   together.

   .. rubric:: Syntax

   .. code-block:: c

      int m_cat(struct mbuf *m1, struct mbuf *m2);

.. option:: m_copyfrombuf

   .. rubric:: Description

   Copy *len* bytes from source buffer *src*, to *mbuf* structure *m* at offset
   *off*. The memory areas should not overlap. If there is not enough room in
   segments, the function automatically allocates segments to store data. The
   *m_copyfrombuf()* function returns the number of copied bytes. If the
   function fails (on segment allocation), the return value can be different
   from *len*.

   If the *off* argument is *m_len(m)*, you can use this function to append data
   to the *mbuf* structure, allocating new segments if necessary.

   .. rubric:: Syntax

   .. code-block:: c

      uint32_t m_copyfrombuf(struct mbuf *m, uint32_t off, const void *src,
      uint32_t len)

.. option:: m_check

   .. rubric:: Description

   Check if an *mbuf* structure is valid, e.g., that *m_len(m)* is equal to the
   sum of *s_len(s)*.

   .. rubric:: Syntax

   .. code-block:: c

      int m_check(const struct mbuf *m)

.. option:: m_copypack

   .. rubric:: Description

   Duplicate an area of a packet in a new *mbuf* structure, starting at offset
   *off* and finishing after *len* bytes.

   On success
      Return the new *mbuf* structure.

   On error
      Return NULL.

   .. rubric:: Syntax

   .. code-block:: c

      struct mbuf *m_copypack(const struct mbuf *m, uint32_t off, uint32_t len)

.. option:: m_headlen(m)

   .. rubric:: Description

   Return the length of the first segment. Equivalent to
   *s_len(m_first_seg(m))*.

   .. rubric:: Syntax

   .. code-block:: c

      uint32_t m_headlen(const struct mbuf *m)

.. option:: m_copytobuf

   .. rubric:: Description

   Copy *len* bytes from source *mbuf* structure *m*, at offset *off*, to memory
   area *dest*. The memory areas should not overlap. The *m_copytobuf()*
   function returns the number of copied bytes.

   - If *off* is higher than *m_len(m)*, the packet and the destination buffer
     are not modified.
   - If *len* is higher than *(m_len(m)-off)*, only *(m_len(m)-off)* bytes are
     copied.

   .. rubric:: Syntax

   .. code-block:: c

      uint32_t m_copytobuf(void *dest, const struct mbuf *m, uint32_t off,
      uint32_t len)

.. option:: m_dump

   .. rubric:: Description

   Display the content of the packet for debugging purposes. If *dump_len* == 0,
   only dump the *mbuf* and *sbuf* structures. Otherwise, dump the *dump_len*
   first data of the packet.

   .. rubric:: Syntax

   .. code-block:: c

      void m_dump(const struct mbuf *m, int dump_len)

.. option:: m_dup

   .. rubric:: Description

   Duplicate the *mbuf* structure *m*. Copy the *input_port* to the new *mbuf*
   structure.

   On error
      Return NULL.

   .. important::

      The private, application-specific part of the *mbuf* structure is also
      copied.

   .. rubric:: Syntax

   .. code-block:: c

      struct mbuf *m_dup(const struct mbuf *m)

.. option:: m_first_seg

   .. rubric:: Description

   Return the first segment descriptor (*sbuf* structure) of an *mbuf*
   structure.

   .. rubric:: Syntax

   .. code-block:: c

      struct sbuf *m_first_seg(struct mbuf *m)

.. option:: m_freem

   .. rubric:: Description

   Free an *mbuf* structure. For chained buffers, also frees all the *mbuf*
   structure's segments.

   .. rubric:: Syntax

   .. code-block:: c

      void m_freem(struct mbuf *m)

.. option:: m_input_port

   .. rubric:: Description

   Return the network input port of the *mbuf* structure.

   .. rubric:: Syntax

   .. code-block:: c

      uint8_t m_input_port(const struct mbuf *m)

.. option:: m_is_contiguous

   .. rubric:: Description

   Return 1 if all data pieces are contiguous in the *mbuf* structure (only one
   buffer), 0 otherwise.

   .. rubric:: Syntax

   .. code-block:: c

      int m_is_contiguous(const struct mbuf *m)

.. option:: m_len

   .. rubric:: Description

   Return the total data length in the *mbuf* structure:

   m_len(m) = SUM (s_len(s1) + s_len(s2) + ... s_len(sn))

   .. rubric:: Syntax

   .. code-block:: c

      uint32_t m_len(const struct mbuf *m)

.. option:: m_maypull

   .. rubric:: Description

   Return the length of continous data pieces starting at *off*.

   .. note::

      You can also use the *M_FOREACH_SEGMENT()* macro, or the *m_copyfrombuf()*
      function.

   .. rubric:: Syntax

   .. code-block:: c

      uint32_t m_maypull(const struct mbuf *m, uint32_t off);

.. option:: m_off

   .. rubric:: Description

   Return a pointer (type *t*) to *data* at *offset*, or NULL if *off* is higher
   than *m_len(m)*.

   .. note::

      - You can also use the *M_FOREACH_SEGMENT()* macro, or the
        *m_copyfrombuf()* function. You can use the *m_off()* function in the
        *memcpy()* function, if you know the size that you can copy (the size of
        the segment).

      - In some cases, the *m_off()* function helps parse a header that is not
        in the first segment. You can also use the *m_maypull()* or the
        *m_pullup(m)* function.

   .. rubric:: Syntax

   .. code-block:: c

      m_off(const struct mbuf *m, uint32_t off, type t)

.. option:: m_prepend

   .. rubric:: Description

   Prepend a space of *len* bytes to the *mbuf* structure data area. Return a
   pointer to the new data start address.

   .. important::

      If there is not enough headroom in the first segment, the function does
      not allocate a new segment and returns NULL, without modifying the *mbuf*
      structure.

   .. rubric:: Syntax

   .. code-block:: c

      char *m_prepend(struct *mbuf* structure *m, unsigned int len)

   .. rubric:: Diagram

   .. figure:: images/m_prepend.svg
       :alt: m_prepend

.. option:: m_pullup

   .. rubric:: Description

   Check that the first *len* bytes of the *mbuf* structure are contiguous. If
   not, reorganize segments in the *mbuf* structure to match this condition.

   On error
      Return NULL. In this case the *mbuf* structure and all its segments are
      freed.

   On success

   Return the mbuf *m* that can be left unmodified (if *len* bytes are already
   contiguous) or have some intermediate segments deleted.

   .. note::

      You cannot pull up more than the maximum segment size, that is
      architecture-dependent (around 2K, usually). If there is room left, the
      function adds up to *m_max_protohdr* extra bytes to the contiguous region
      to try to avoid being called next time.

   .. rubric:: Syntax

   .. code-block:: c

      struct mbuf *m_pullup(struct mbuf *m, uint32_t len);

.. _m_save_mac_m_restore_mac:

.. option:: m_save_mac / m_restore_mac

   .. rubric:: Description

   Depending on your architecture, the *m_adj()* function may modify the content
   of *adjusted* data. That is why the following code may not work:

   .. code-block:: c

      m_adj(m, sizeof(struct fp_ether_header));

      /* code that does not modify m */

      m_prepend(m, sizeof(struct fp_ether_header));
      fp_send_exception(m, port);

   The correct code is:

   .. code-block:: c

      m_save_mac(m);
      m_adj(m, sizeof(struct fp_ether_header));

      /* code that does not modify m */

      m_prepend(m, sizeof(struct fp_ether_header));
      m_restore_mac(m);
      fp_send_exception(m, port);

   .. note::

      - This only applies to:

        - Ethernet packets
        - one call of the *m_adj()* or *m_prepend()* functions

      - *m_save_mac* and *m_restore_mac* fuctions are called on the same *mbuf*
        structure
      - Adjusted len is sizeof(struct fp_ether_header) == 14

      .. important::

         This macro only applies to Octeon (the 8 bytes that are overridden by
         the *next* pointer are saved in the work queue entry). It does nothing
         on other architectures.

   .. rubric:: Syntax

   .. code-block:: c

      void m_save_mac(struct mbuf *m)
       void m_restore_mac(struct mbuf *m)

.. option:: m_seg_count

   .. rubric:: Description

   Return the number of segments in an *mbuf* structure.

   .. rubric:: Syntax

   .. code-block:: c

      int m_seg_count(const struct mbuf *m)

.. option:: m_set_egress_color / m_get_egress_color

   .. rubric:: Description

   Get and set color for egress.

   .. rubric:: Syntax

   .. code-block:: c

      void m_set_egress_color(struct mbuf *, const uint8_t color)
      uint8_t m_get_egress_color(const struct mbuf *m)

.. option:: m_set_input_port

   .. rubric:: Description

   Set the network input port of the *mbuf* structure.

   .. rubric:: Syntax

   .. code-block:: c

      void m_set_input_port(struct mbuf *m, uint8_t port)

.. option:: m_shrink

   .. rubric:: Description

   Reorganize segments in the *mbuf* structure to insert as much data as
   possible in each segment.

   On error
      Return NULL; free the *mbuf* structure and all its segments.

   On success
      Return the *mbuf* structure *m*.

   .. rubric:: Syntax

   .. code-block:: c

      struct mbuf *m_shrink(struct mbuf *m);

.. option:: m_split

   .. rubric:: Description

   Split an *mbuf* structure in two *mbuf* structures at offset *off*.

   Let's call *m1* the original *mbuf* structure, and *m2* the returned *mbuf*
   structure. The function allocates a new buffer *m2* and copies from *m1* the
   minimum amount of data at offset *off* to the first segment of *m2*. The last
   segments of *m1* are relinked to *m2*.

   On error
      Return NULL and do not modify *m1*.

   If off == 0 or off >= len
      Return NULL.

   .. rubric:: Syntax

   .. code-block:: c

      struct mbuf *m_split(struct mbuf *m, uint32_t off)

.. option:: m_tail

   .. rubric:: Description

   Return a pointer just after the end of the data piece. The pointer can be
   located in a segment other than the start of the data piece.

   .. rubric:: Syntax

   .. code-block:: c

      char *m_tail(const struct mbuf *m)

.. option:: m_trim

   .. rubric:: Description

   Remove *len* bytes of data at the end of the *mbuf* structure.

   If *len* is higher than the *len* of the last *segment*
      Remove and free the segments.

   If *len* >= m_len(m)
      Fail and return 0.

   .. rubric:: Syntax

   .. code-block:: c

      uint32_t m_trim(struct mbuf *m, uint32_t len)

   .. rubric:: Diagram

   .. figure:: images/m_trim.svg
       :alt: m_trim

.. option:: mtod

   .. rubric:: Description

   Macro that points to the start of data in the *mbuf* structure. The returned
   pointer is cast to type *t*.

   .. important::

      Before using this function, make sure that the *m_headlen(m)* value is
      large enough to read the data it returns.

   .. rubric:: Syntax

   .. code-block:: c

      mtod(const struct mbuf *m, type t)

.. option:: s_data

   .. rubric:: Description

   Macro that points to the start of data in segment *s*. The returned pointer
   is cast to type *t*.

   .. rubric:: Syntax

   .. code-block:: c

      s_data(struct sbuf *s, type t)

.. option:: s_len

   .. rubric:: Description

   Return the length of the segment s, owned by mbuf m.

   .. rubric:: Syntax

   .. code-block:: c

      uint32_t s_len(struct sbuf *s)

.. option:: s_next

   .. rubric:: Description

   In packet *m*, return the next segment descriptor after *s*. If there is no
   next segment, return NULL.

   .. rubric:: Syntax

   .. code-block:: c

      struct sbuf *s_next(struct mbuf *m, struct sbuf *s)
