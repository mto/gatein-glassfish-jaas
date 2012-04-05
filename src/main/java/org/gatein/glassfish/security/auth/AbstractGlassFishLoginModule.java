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
import org.exoplatform.container.ExoContainer;
import org.exoplatform.container.ExoContainerContext;
import org.exoplatform.container.PortalContainer;
import org.exoplatform.container.RootContainer;

/**
 * @author <a href="hoang281283@gmail.com">Minh Hoang TO</a>
 * @date 4/2/12
 */
public abstract class AbstractGlassFishLoginModule extends AppservPasswordLoginModule
{

   private static final String OPTION_PORTAL_CONTAINER_NAME = "portalContainerName";

   public ExoContainer getContainer()
   {
      ExoContainer container = ExoContainerContext.getCurrentContainer();
      if (container instanceof RootContainer)
      {
         String portalContainerName = getPortalContainerName();
         container = RootContainer.getInstance().getPortalContainer(portalContainerName);
         if (container == null)
         {
            throw new RuntimeException("The eXo container is null, because the current container is a RootContainer "
               + "and there is no PortalContainer with the name '" + portalContainerName + "'.");
         }
      }
      else if (container == null)
      {
         throw new RuntimeException("The eXo container is null, because the current container is null.");
      }
      return container;
   }

   private String getPortalContainerName()
   {
      if (_options != null)
      {
         String optionValue = (String)_options.get(OPTION_PORTAL_CONTAINER_NAME);
         if (optionValue != null && optionValue.length() > 0)
         {
            return optionValue;
         }
      }
      return PortalContainer.DEFAULT_PORTAL_CONTAINER_NAME;
   }
}
