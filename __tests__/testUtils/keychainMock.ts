// keychainMock.ts — Shared replacement for react-native-keychain in tests: a simple in-memory
// store that serves the same interface as the native module. It is wired in via
// `jest.mock('react-native-keychain', () => require('./testUtils/keychainMock').createInMemoryKeychainMock())`
// — as a require() inside the factory, because jest.mock factories do not allow closures over
// module imports (Babel hoisting). NOTE: the mock ignores `securityLevel`/`accessControl`, so the
// tests do not exercise real Android Keystore or biometric behavior.
export function createInMemoryKeychainMock() {
  const store = new Map<string, {username: string; password: string}>();

  return {
    SECURITY_LEVEL: {
      SECURE_HARDWARE: 'SECURE_HARDWARE',
      SECURE_SOFTWARE: 'SECURE_SOFTWARE',
      ANY: 'ANY',
    },
    STORAGE_TYPE: {AES_GCM_NO_AUTH: 'AES_GCM_NO_AUTH'},
    ACCESS_CONTROL: {
      BIOMETRY_ANY_OR_DEVICE_PASSCODE: 'BiometryAnyOrDevicePasscode',
    },
    BIOMETRY_TYPE: {
      TOUCH_ID: 'TouchID',
      FACE_ID: 'FaceID',
      OPTIC_ID: 'OpticID',
      FINGERPRINT: 'Fingerprint',
      FACE: 'Face',
      IRIS: 'Iris',
    },
    setGenericPassword: jest.fn(
      async (
        username: string,
        password: string,
        options: {service: string},
      ) => {
        store.set(options.service, {username, password});
        return {service: options.service, storage: 'AES_GCM_NO_AUTH'};
      },
    ),
    getGenericPassword: jest.fn(async (options: {service: string}) => {
      const entry = store.get(options.service);
      if (!entry) {
        return false;
      }
      return {...entry, service: options.service, storage: 'AES_GCM_NO_AUTH'};
    }),
    hasGenericPassword: jest.fn(async (options: {service: string}) => {
      return store.has(options.service);
    }),
    resetGenericPassword: jest.fn(async (options?: {service: string}) => {
      if (options?.service) {
        store.delete(options.service);
      }
      return true;
    }),
    getSupportedBiometryType: jest.fn(async () => null),
  };
}
