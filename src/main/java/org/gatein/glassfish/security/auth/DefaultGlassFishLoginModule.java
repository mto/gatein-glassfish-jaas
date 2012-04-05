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
import org.exoplatform.services.security.IdentityRegistry;
import org.exoplatform.services.security.PasswordCredential;
import org.exoplatform.services.security.UsernameCredential;
import org.exoplatform.services.security.jaas.RolePrincipal;
import org.exoplatform.services.security.jaas.UserPrincipal;
import java.security.Principal;
import java.util.Set;
import javax.security.auth.login.LoginException;

/**
 * @author <a href="hoang281283@gmail.com">Minh Hoang TO</a>
 * @date 4/2/12
 */
public class DefaultGlassFishLoginModule extends AbstractGlassFishLoginModule
{

   private Identity identity;

   @Override
   protected void authenticateUser() throws LoginException
   {
      try
      {
         if (_sharedState.containsKey("exo.security.identity"))
         {
            identity = (Identity)_sharedState.get("exo.security.identity");
         }
         else
         {
            String username = getUsername();
            String password = new String(getPasswordChar());
            Authenticator authenticator = (Authenticator)getContainer().getComponentInstanceOfType(Authenticator.class);

            if (authenticator == null)
            { throw new LoginException("No Authenticator component found, check your configuration"); }

            Credential[] credentials =
               new Credential[]{new UsernameCredential(username), new PasswordCredential(password)};

            String userId = authenticator.validateUser(credentials);
            identity = authenticator.createIdentity(userId);
            _sharedState.put("javax.security.auth.login.name", userId);
            // TODO use PasswordCredential wrapper
            _subject.getPrivateCredentials().add(password);
            _subject.getPublicCredentials().add(new UsernameCredential(username));
         }
      }
      catch (Throwable e)
      {
         throw new LoginException(e.getMessage());
      }
   }

   @Override
   public boolean commit() throws LoginException
   {
      try
      {
         String sl = (String)_options.get("singleLogin");
         boolean singleLogin = (sl != null && (sl.equalsIgnoreCase("yes") || sl.equalsIgnoreCase("true")));

         IdentityRegistry identityRegistry =
            (IdentityRegistry)getContainer().getComponentInstanceOfType(IdentityRegistry.class);

         if (singleLogin && identityRegistry.getIdentity(identity.getUserId()) != null)
         { throw new LoginException("User " + identity.getUserId() + " already logined."); }
         identity.setSubject(_subject);
         identityRegistry.register(identity);

         Set<Principal> principals = _subject.getPrincipals();
         for (String role : identity.getRoles())
         { principals.add(new RolePrincipal(role)); }

         principals.add(new UserPrincipal(identity.getUserId()));

         return true;
      }
      catch (Throwable e)
      {
         throw new LoginException(e.getMessage());
      }
   }
}
