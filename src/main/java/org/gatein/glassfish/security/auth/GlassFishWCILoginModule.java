/*
 * Copyright (C) 2012 eXo Platform SAS.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.gatein.glassfish.security.auth;

import com.sun.appserv.security.AppservPasswordLoginModule;
import org.gatein.wci.authentication.GenericAuthentication;
import org.gatein.wci.security.Credentials;
import javax.security.auth.login.LoginException;

/**
 * @author <a href="hoang281283@gmail.com">Minh Hoang TO</a>
 * @date 4/2/12
 */
public class GlassFishWCILoginModule extends AppservPasswordLoginModule
{
   @Override
   protected void authenticateUser() throws LoginException
   {
      try
      {
         Credentials credentials = GenericAuthentication.TICKET_SERVICE.validateTicket(new String(getPasswordChar()), true);
         _sharedState.put("javax.security.auth.login.name", credentials.getUsername());
         _sharedState.put("javax.security.auth.login.password", credentials.getPassword());
      }
      catch (Exception e)
      {
         LoginException le = new LoginException();
         le.initCause(e);
         throw le;
      }
   }
}
