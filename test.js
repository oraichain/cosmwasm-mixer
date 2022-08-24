const fs = require('fs');
const { execSync } = require('child_process');
const path = require('path');

const [test] = process.argv.slice(2);

try {
  execSync(
    `cargo test --lib --package cosmwasm-mixer ${process.argv
      .slice(3)
      .join(' ')} -- tests::${test} --exact --nocapture`,
    { stdio: 'inherit' }
  );
} catch (ex) {
  console.log(ex.message);
}
