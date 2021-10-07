/*
 * Tigase XMPP Server - The instant messaging server
 * Copyright (C) 2004 Tigase, Inc. (office@tigase.com)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. Look for COPYING file in the top folder.
 * If not, see http://www.gnu.org/licenses/.
 */
package tigase.stats;

import java.time.LocalDate;
import java.util.AbstractQueue;
import java.util.ArrayDeque;
import java.util.Iterator;
import java.util.Optional;
import java.util.concurrent.ConcurrentLinkedDeque;

/**
 * A queue implementation which stores highest added value on a given day
 * and has limited size.
 */
public class MaxDailyCounterQueue<E extends Number & Comparable<E>>
		extends AbstractQueue<E> {

	private final int maxQueueLength;
	private ConcurrentLinkedDeque<E> deque = new ConcurrentLinkedDeque<>();
	private LocalDate lastDailyStatsReset = LocalDate.now();
	private String toString = "[]";

	public MaxDailyCounterQueue(int maxQueueLength) {
		this.maxQueueLength = maxQueueLength;
	}

	public Optional<E> getMaxValue() {
		return getMaxValueInRange(maxQueueLength);
	}

	public Optional<E> getMaxValueInRange(int range) {
		range = Math.min(range, maxQueueLength);

		E result = null;
		final Iterator<E> iterator = deque.descendingIterator();
		while (iterator.hasNext() && range > 0) {
			range--;

			final E next = iterator.next();
			if (result == null || next.compareTo(result) > 0) {
				result = next;
			}
		}
		return Optional.ofNullable(result);
	}

	/**
	 * Check if <b>any</b> item in the collection surpass the limit
	 *
	 * @param limit against which items should be check
	 *
	 * @return indicating whether <b>any</b> item in the collection surpass the limit
	 */
	public boolean isLimitSurpassed(E limit) {
		return isLimitSurpassed(maxQueueLength, limit);
	}

	/**
	 * Check if <b>any</b> item within range surpass the limit
	 *
	 * @param range number of items to check
	 * @param limit against which items should be check
	 *
	 * @return indicating whether <b>any</b> item within range surpass the limit
	 */
	public boolean isLimitSurpassed(int range, E limit) {
		return getMaxValueInRange(range).filter(e -> e.compareTo(limit) > 0).isPresent();
	}

	/**
	 * Check if all and every item in the collection surpass the limit
	 *
	 * @param limit against which items should be check
	 *
	 * @return indicating whether all items in the collection surpass the limit
	 */
	public boolean isLimitSurpassedAllItems(E limit) {
		return isLimitSurpassedAllItems(maxQueueLength, limit);
	}

	/**
	 * Check if all and every item within range surpass the limit
	 *
	 * @param range number of items to check
	 * @param limit against which items should be check
	 *
	 * @return indicating whether all items <b>within range</b> surpass the limit
	 */
	public boolean isLimitSurpassedAllItems(int range, E limit) {
		boolean result = true;
		range = Math.min(range, maxQueueLength);

		final Iterator<E> iter = deque.descendingIterator();
		while (iter.hasNext() && range > 0) {
			range--;

			final E next = iter.next();
			if (next.compareTo(limit) <= 0) {
				result &= false;
			}
		}
		return result;
	}

	@Override
	public Iterator<E> iterator() {
		return deque.iterator();
	}

	@Override
	public boolean offer(E added) {
		if (isNextItem() || deque.peekLast() == null) {
			deque.offer(added);
		} else if (deque.peekLast().compareTo(added) < 0) {
			deque.pollLast();
			deque.offer(added);
		}
		while (deque.size() > maxQueueLength) {
			deque.remove();
		}
		toString = deque.toString();
		return true;
	}

	@Override
	public E peek() {
		return deque.peek();
	}

	@Override
	public E poll() {
		return deque.poll();
	}

	@Override
	public int size() {
		return deque.size();
	}

	public ArrayDeque<E> subQueue(int range) {
		final ArrayDeque<E> result = new ArrayDeque<E>(range);
		range = Math.min(range, maxQueueLength);

		final Iterator<E> iter = deque.descendingIterator();
		while (iter.hasNext() && range > 0) {
			range--;
			result.add(iter.next());
		}
		return result;
	}

	@Override
	public String toString() {
		return toString;
	}

	protected boolean isNextItem() {
		LocalDate now = LocalDate.now();
		if (now.getYear() != lastDailyStatsReset.getYear() ||
				now.getDayOfYear() != lastDailyStatsReset.getDayOfYear()) {
			lastDailyStatsReset = LocalDate.now();
			return true;
		} else {
			return false;
		}
	}
}
