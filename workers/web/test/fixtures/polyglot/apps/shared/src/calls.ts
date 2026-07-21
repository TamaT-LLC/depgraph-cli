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

// This class deliberately has no constructor, fields, accessors, static
// blocks, decorators, inherited members, or non-method members. It is the
// release-fixture proof that a closed local fresh-instance receiver can be
// enumerated without relying on construction-time mutation.
export class ClosedFreshReceiver {
  closedMethod(value: string): string {
    return value;
  }
}

export function exerciseCalls(value: string): string {
  const receiver = new DirectReceiver("open:");
  const candidateReceiver = new ClosedFreshReceiver();
  const dynamicTarget = (input: string): string => input;
  const firstConditionalTarget = (input: string): string => input;
  const secondConditionalTarget = (input: string): string => input;
  const conditionalTarget = value ? firstConditionalTarget : secondConditionalTarget;
  const direct = directTarget(value);
  const staticResult = DirectReceiver.staticTarget(value);
  const freshResult = new DirectReceiver("fresh:").directMethod(value);
  const openResult = receiver.directMethod(value);
  const candidateResult = candidateReceiver.closedMethod(value);
  const dynamicResult = dynamicTarget(value);
  const conditionalResult = conditionalTarget(value);
  const externalResult = value.trim();
  return [direct, staticResult, freshResult, openResult, candidateResult, dynamicResult, conditionalResult, externalResult].join(":");
}
