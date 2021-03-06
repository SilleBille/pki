// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2014 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.ca.rest;

import org.dogtagpki.server.ca.CAConfigurator;
import org.dogtagpki.server.rest.SystemConfigService;

/**
 * @author alee
 *
 */
public class CAInstallerService extends SystemConfigService {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CAInstallerService.class);

    public CAConfigurator caConfigurator;

    public CAInstallerService() throws Exception {
        caConfigurator = (CAConfigurator) configurator;
    }
}
