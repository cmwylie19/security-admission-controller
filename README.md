# Security Admission Control

DEMO 
- [build](#build-the-module)
- [deploy](#deploy-the-module)
- [test](#run-tests)
- [links](#links)
## Build the module

```bash
npx pepr build
```

### Deploy the module

```bash
kubectl create -f ./dist
```

### Run tests

k3d cluster create
```bash
k3d cluster create admission-test 
```

Build the module 
```bash
npx pepr build
kubectl create -f ./dist
kubectl wait --for=condition=Ready pod -l pepr.dev/controller -n pepr-system  
```

Run the tests
```bash
npm run test
```

Clean up
```bash
k3d cluster delete admission-test
```

## Links

- [GitHub](https://github.com/defenseunicorns/pepr)
- [Pepr Website](https://pepr.dev)
- [Defense Unicorns](https://defenseunicorns.com)
