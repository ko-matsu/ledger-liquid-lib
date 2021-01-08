import { spawn } from 'child_process'
import webpack from 'webpack'
import { merge } from 'webpack-merge'
import { renderer } from './webpack.config'
import { args } from './utils'

const publicPath = `http://localhost:${args.devport}/dist`

export default merge(
  {
    mode: 'development',
    entry: [
      'react-hot-loader/patch',
      `webpack-dev-server/client?http://localhost:${args.devport}`,
      'webpack/hot/only-dev-server'
    ],

    output: {
      publicPath
    },

    plugins: [new webpack.HotModuleReplacementPlugin()],

    devtool: 'inline-source-map',

    //@ts-ignore
    devServer: {
      port: args.devport,
      publicPath,
      historyApiFallback: true,
      hot: true,
      after() {
        // eslint-disable-next-line no-console
        console.log('Starting Main Process...')
        spawn('electron', ['./dist/main.js'], {
          shell: true,
          env: process.env,
          stdio: 'inherit'
        })
          .on('error', spawnError => console.error(spawnError))
      }
    }
  },
  renderer
)
