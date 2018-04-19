#ifndef __NT_LIST_H__
#define __NT_LIST_H__



/*! \brief structure that must be placed at the begining of any structure
 *         that is to be put into the linked list.
 */
typedef struct _nt_list {
	struct _nt_list *next;   /**< next pointer */
	struct _nt_list *prev;   /**< previous pointer */
} nt_list;


/** Initialize a field in a structure that is used as the head of a dlist */
#define NT_LIST_HEAD_IN_STRUCT_INIT(field) do {\
      (field).next = &(field);               \
      (field).prev = &(field);               \
   } while (0)

/** Initialize a standalone variable that is the head of a dlist */
#define NT_LIST_HEAD_INIT(name) { &(name), &(name) }

/** Declare a standalone variable that is the head of the dlist */
#define NT_LIST_HEAD(name) \
	struct _nt_list name = NT_LIST_HEAD_INIT(name)


static inline void nt_list_init(struct _nt_list *list)
{
    list->next = list;
    list->prev = list;
}


/** Return true if the dlist is empty.
 *
 * @param head pointer to the head of the dlist.
 */
static inline int nt_list_empty(const struct _nt_list *head)
{
	return ((head->next == head) && (head->prev == head));
}


/** add a new entry after an existing list element
 *
 * @param new       new entry to be added
 * @param existing  list element to add the new entry after.  This could
 *                  be the list head or it can be any element in the dlist.
 *
 */
static inline void nt_list_append(struct _nt_list *new, struct _nt_list *existing)
{
   existing->next->prev = new;

   new->next = existing->next;
   new->prev = existing;

   existing->next = new;
}


/** add a new entry in front of an existing list element
 *
 * @param new       new entry to be added
 * @param existing  list element to add the new entry in front of.  This could
 *                  be the list head or it can be any element in the dlist.
 *
 */
static inline void nt_list_prepend(struct _nt_list *new, struct _nt_list *existing)
{
   existing->prev->next = new;

   new->next = existing;
   new->prev = existing->prev;

   existing->prev = new;
}


/** Unlink the specified entry from the list.
 *  This function does not free the entry.  Caller is responsible for
 *  doing that if applicable.
 *
 * @param entry existing dlist entry to be unlinked from the dlist.
 */
static inline void nt_list_unlink(struct _nt_list *entry)
{
   entry->next->prev = entry->prev;
   entry->prev->next = entry->next;

	entry->next = 0;
	entry->prev = 0;
}

#undef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)


#define container_of(ptr, type, member) ({			\
        const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
        (type *)( (char *)__mptr - offsetof(type,member) );})


#define nt_list_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define nt_list_entry_first(ptr, type, member) container_of((ptr)->next, type, member)


#define nt_list_for_each_entry(pos, head, member)				\
	for (pos = nt_list_entry((head)->next, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = nt_list_entry(pos->member.next, typeof(*pos), member))

#define nt_list_for_each_entry_safe(pos, tmp, head, member)				\
        for (pos = nt_list_entry((head)->next, typeof(*pos), member),\
             tmp = nt_list_entry(pos->member.next, typeof(*pos), member); \
             &pos->member != (head);                    \
             pos = tmp, tmp = nt_list_entry(pos->member.next, typeof(*pos), member))


#endif  /*__NT_LIST_H__ */

