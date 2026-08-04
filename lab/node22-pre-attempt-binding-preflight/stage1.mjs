export function launchSyntheticStage1() {
  const error = new Error('synthetic stage-1 launch failure');
  error.code = 'SYNTHETIC_STAGE1_LAUNCH_FAILED';
  error.syscall = 'synthetic-stage1-launch';
  throw error;
}
