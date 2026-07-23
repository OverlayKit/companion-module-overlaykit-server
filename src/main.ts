import {
  InstanceBase,
  InstanceStatus,
  type CompanionStaticUpgradeScript,
  type SomeCompanionConfigField,
} from '@companion-module/base';
import { updateActions, type ActionsSchema } from './actions.js';
import {
  getConfigFields,
  ModuleConfigurationError,
  type ModuleConfig,
  type ModuleSecrets,
} from './config.js';
import { updateFeedbacks, type FeedbacksSchema } from './feedbacks.js';
import {
  OverlayKitControlRuntime,
  type RuntimeConnectionStatus,
  type VisibilityBinding,
  type VisibilityFeedbackState,
  type VisibilityMode,
} from './runtime.js';

export type ModuleSchema = {
  config: ModuleConfig;
  secrets: ModuleSecrets;
  actions: ActionsSchema;
  feedbacks: FeedbacksSchema;
  variables: Record<string, never>;
};

export const UpgradeScripts: CompanionStaticUpgradeScript<ModuleConfig, ModuleSecrets>[] = [];

function instanceStatus(status: RuntimeConnectionStatus): InstanceStatus {
  switch (status) {
    case 'ready':
      return InstanceStatus.Ok;
    case 'connecting':
    case 'open':
      return InstanceStatus.Connecting;
    case 'disconnected':
    case 'idle':
      return InstanceStatus.Disconnected;
    case 'failed':
      return InstanceStatus.ConnectionFailure;
  }
}

export default class ModuleInstance extends InstanceBase<ModuleSchema> {
  private readonly runtime = new OverlayKitControlRuntime({
    onStatusChanged: (status, message) => this.updateStatus(instanceStatus(status), message),
    onDefinitionsChanged: () => {
      this.updateActions();
      this.updateFeedbacks();
    },
    onFeedbackChanged: () => this.checkFeedbacks('visibility.state'),
    onLog: (level, message) => this.log(level, message),
  });

  constructor(internal: unknown) {
    super(internal);
  }

  async init(config: ModuleConfig, _isFirstInit: boolean, secrets: ModuleSecrets): Promise<void> {
    this.updateActions();
    this.updateFeedbacks();
    await this.reconfigure(config, secrets);
  }

  async destroy(): Promise<void> {
    await this.runtime.stop();
  }

  async configUpdated(config: ModuleConfig, secrets: ModuleSecrets): Promise<void> {
    await this.reconfigure(config, secrets);
  }

  getConfigFields(): SomeCompanionConfigField[] {
    return getConfigFields();
  }

  runtimeBindings(): ReadonlyArray<VisibilityBinding> {
    return this.runtime.bindings();
  }

  visibilityFeedback(bindingId: string): VisibilityFeedbackState {
    return this.runtime.feedback(bindingId);
  }

  async executeVisibility(mode: VisibilityMode, bindingId: string): Promise<void> {
    await this.runtime.execute(mode, bindingId);
  }

  private updateActions(): void {
    updateActions(this);
  }

  private updateFeedbacks(): void {
    updateFeedbacks(this);
  }

  private async reconfigure(config: ModuleConfig, secrets: ModuleSecrets): Promise<void> {
    try {
      await this.runtime.start(config, secrets);
    } catch (error) {
      if (error instanceof ModuleConfigurationError) {
        this.updateStatus(InstanceStatus.BadConfig, error.message);
        this.log('warn', error.message);
        return;
      }
      this.updateStatus(InstanceStatus.UnknownError, 'OverlayKit module initialization failed');
      this.log('error', 'OverlayKit module initialization failed');
    }
  }
}
