/*
 * Copyright (c) 1999, 2024, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

/**
 * <p>Provides the definition of the Timer MBean.  A Timer MBean
 * maintains a list of scheduled notifications and, because it is a
 * {@link javax.management.NotificationBroadcaster
 * NotificationBroadcaster}, a list of listeners for those
 * notifications.  Whenever the time for one of the scheduled
 * notifications is reached, each listener receives the
 * notification.  Notifications can be repeated at a fixed
 * interval, and the number of repetitions can be bounded.</p>
 *
 * <p>A listener for a Timer MBean can itself be an MBean, using
 * the method {@link
 * javax.management.MBeanServer#addNotificationListener(ObjectName,
 * ObjectName, NotificationFilter, Object)}.  In this way, a
 * management application can create an MBean representing a task,
 * then schedule that task using a Timer MBean.</p>
 *
 * @since 1.5
 */
package javax.management.timer;
