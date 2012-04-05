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

import org.exoplatform.services.security.Authenticator;
import org.exoplatform.services.security.Credential;
import org.exoplatform.services.security.Identity;
import org.exoplatform.services.security.PasswordCredential;
import org.exoplatform.services.security.UsernameCredential;
import javax.security.auth.login.LoginException;

/**
 * @author <a href="hoang281283@gmail.com">Minh Hoang TO</a>
 * @date 4/2/12
 */
public class GlassFishSharedStateLoginModule extends AbstractGlassFishLoginModule
{

   @Override
   protected void authenticateUser() throws LoginException
   {
      try
      {
         String username = (String)_sharedState.get("javax.security.auth.login.name");
         String password = (String)_sharedState.get("javax.security.auth.login.password");

         Authenticator authenticator = (Authenticator)getContainer().getComponentInstanceOfType(Authenticator.class);

         if (authenticator == null)
         { throw new LoginException("No Authenticator component found, check your configuration"); }

         Credential[] credentials =
            new Credential[]{new UsernameCredential(username), new PasswordCredential(password)};

         String userId = authenticator.validateUser(credentials);
         Identity identity = authenticator.createIdentity(userId);

         _sharedState.put("exo.security.identity", identity);
         _sharedState.put("javax.security.auth.login.name", userId);
         // TODO use PasswordCredential wrapper
         _subject.getPrivateCredentials().add(password);
         _subject.getPublicCredentials().add(new UsernameCredential(username));
      }
      catch (final Throwable e)
      {
         LoginException le = new LoginException(e.getMessage());
         le.initCause(e);
         throw le;
      }
   }
}
