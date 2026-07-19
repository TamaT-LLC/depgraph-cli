export function directTarget(value: string): string {
  return value;
}

export class DirectReceiver {
  constructor(readonly prefix: string) {}

  static staticTarget(value: string): string {
    return value;
  }

  directMethod(value: string): string {
    return `${this.prefix}${value}`;
  }
}

export function exerciseCalls(value: string): string {
  const receiver = new DirectReceiver("open:");
  const dynamicTarget = (input: string): string => input;
  const direct = directTarget(value);
  const staticResult = DirectReceiver.staticTarget(value);
  const freshResult = new DirectReceiver("fresh:").directMethod(value);
  const openResult = receiver.directMethod(value);
  const dynamicResult = dynamicTarget(value);
  const externalResult = value.trim();
  return [direct, staticResult, freshResult, openResult, dynamicResult, externalResult].join(":");
}
