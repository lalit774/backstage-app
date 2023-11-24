import { createRouter } from '@backstage/plugin-permission-backend';
import { BackstageIdentityResponse } from '@backstage/plugin-auth-node';
import {
  AuthorizeResult,
  PolicyDecision,
} from '@backstage/plugin-permission-common';
import {
  PermissionPolicy,
  PolicyQuery,
} from '@backstage/plugin-permission-node';
import { Router } from 'express';
import { PluginEnvironment } from '../types';
import { isPermission } from '@backstage/plugin-permission-common';
import { todoListCreatePermission } from '@internal/plugin-todo-list-common';

class TestPermissionPolicy implements PermissionPolicy {
  async handle(
    request: PolicyQuery,
    _user?: BackstageIdentityResponse,
  ): Promise<PolicyDecision> {
    if (isPermission(request.permission, todoListCreatePermission)) {
      return {
        result: AuthorizeResult.DENY,
      };
    }

    return { result: AuthorizeResult.ALLOW };
  }
}

export default async function createPlugin(
  env: PluginEnvironment,
): Promise<Router> {
  return await createRouter({
    config: env.config,
    logger: env.logger,
    discovery: env.discovery,
    policy: new TestPermissionPolicy(),
    identity: env.identity,
  });
}
