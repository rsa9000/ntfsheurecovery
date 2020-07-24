/**
 * Double linked list implementation
 *
 * Copyright (c) 2015, Sergey Ryazanov <ryazanov.s.a@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _LIST_H_
#define _LIST_H_

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

#define list_for_each(pos, head)				\
		for (pos = head->next; pos != head; pos = pos->next)

#define list_for_each_safe(pos, tmp, head)			\
		for (pos = head->next, tmp = pos->next;		\
		     pos != head;				\
		     pos = tmp, tmp = tmp->next)

#define list_entry(ptr, type, field)				\
		((type *)((void *)(ptr) - __builtin_offsetof(type, field)))

#define list_first_entry(head, type, field)			\
		list_entry((head)->next, type, field)

#define list_last_entry(head, type, field)			\
		list_entry((head)->prev, type, field)

#define list_next_entry(ptr, field)				\
		list_entry((ptr)->field.next, typeof(*(ptr)), field)

#define list_prev_entry(ptr, field)				\
		list_entry((ptr)->field.prev, typeof(*(ptr)), field)

#define list_for_each_entry(pos, head, field)			\
		for (pos = list_first_entry(head, typeof(*pos), field);\
		     &pos->field != head;				\
		     pos = list_next_entry(pos, field))

#define list_for_each_entry_reverse(pos, head, field)			\
		for (pos = list_last_entry(head, typeof(*pos), field);	\
		     &pos->field != head;				\
		     pos = list_prev_entry(pos, field))

#define list_for_each_entry_safe(pos, tmp, head, field)		\
		for (pos = list_first_entry(head, typeof(*pos), field),\
		     tmp = list_next_entry(pos, field);\
		     &pos->field != head;			\
		     pos = tmp, tmp = list_next_entry(pos, field))

static inline void INIT_LIST_HEAD(struct list_head *head)
{
	head->prev = head;
	head->next = head;
}

static inline void __list_add(struct list_head *prev, struct list_head *new,
			      struct list_head *next)
{
	new->prev = prev;
	new->next = next;
	next->prev = new;
	prev->next = new;
}

static inline void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(head, new, head->next);
}

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	__list_add(head->prev, new, head);
}

static inline void list_del(struct list_head *head)
{
	head->next->prev = head->prev;
	head->prev->next = head->next;
}

static inline int list_empty(const struct list_head *head)
{
	return head->next == head;
}

#endif	/* _LIST_H_ */
