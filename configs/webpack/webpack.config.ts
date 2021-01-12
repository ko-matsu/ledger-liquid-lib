import path from 'path'
import HtmlWebpackPlugin from 'html-webpack-plugin'
import webpack from 'webpack'
import CopyPlugin from 'copy-webpack-plugin'
import { args } from './utils'

const BOOT_USER_TYPE = args.usertype

const mode =
  process.env.NODE_ENV === 'development' ? 'development' : process.env.NODE_ENV === 'production' ? 'production' : 'none'

const GREEN = '\u001b[32m'
const COLOR_RESET = '\u001b[0m'

console.info(GREEN)
console.info(`webpack for main and renderer`)
console.info(`Webpack mode: ${mode}`)
console.info(`NODE ENV: ${process.env.NODE_ENV}`)
console.info(`Is this packaging?: ${process.env.PACKAGE ? true : false}`)
console.info(COLOR_RESET)

export const main: webpack.Configuration = {
  mode,
  entry: [
    './src/main.ts',
    './src/mutex.ts',
    './src/ledger-liquid-lib.js',
    './src/ledger.ts'
  ],

  output: {
    path: path.join(__dirname, '../..', 'dist'),
    filename: 'main.js'
  },

  devtool: 'inline-source-map',
  target: 'electron-main',

  externals: {
    bindings: 'commonjs bindings',
    'cfd-js': 'commonjs cfd-js',
    usb: 'commonjs usb',
    'usb-detection': 'commonjs usb-detection'
  },

  node: {
    __dirname: false,
    __filename: false
  },

  resolve: {
    alias: {
      src: path.join(__dirname, '../..', 'src'),
      '@shared': path.join(__dirname, '../..', 'src/shared'),
      '@main': path.join(__dirname, '../..', 'src/main')
    },
    extensions: ['.webpack.js', '.web.js', '.ts', '.tsx', '.js', '.json', '.node']
  },

  module: {
    rules: [
      {
        test: /\.tsx?$/,
        loaders: ['ts-loader']
      },
      {
        test: /\.node$/,
        use: 'node-loader'
      }
    ]
  },

  plugins: [
    new CopyPlugin({
      patterns: [
        {
          from: path.join(__dirname, '../../', 'node_modules/cfd-js/build/Release/'),
          to: path.join(__dirname, '../../', 'build/Release'),
          context: path.join(__dirname, '../../', 'dist')
        },
        {
          from: path.join(__dirname, '../../', 'node_modules/usb/build/Release/usb_bindings.node'),
          to: path.join(__dirname, '../../', 'build/Release'),
          context: path.join(__dirname, '../../', 'dist')
        },
        {
          from: path.join(__dirname, '../../', 'node_modules/node-hid/build/Release/HID.node'),
          to: path.join(__dirname, '../../', 'build/Release'),
          context: path.join(__dirname, '../../', 'dist')
        }
      ]
    })
  ]
}

export const renderer: webpack.Configuration = {
  mode,
  entry: {
    renderer: './src/renderer.ts'
  },

  // NOTE(@cg-kento):
  // 基本的にdev環境ではwebpack-dev-serverを用いてるためrendererの読み込み先がdevportになる。
  // dev環境でpackageして動作確認する場合は環境変数のPACKAGEをtrueにすれば良い。
  output:
    !process.env.PACKAGE
      ? {
          publicPath: `http://localhost:${args.devport}/dist`,
          filename: '[name].js'
        }
      : {
          path: path.join(__dirname, '../..', 'dist'),
          filename: '[name].js'
        },

  devtool: 'inline-source-map',
  target: 'electron-renderer',

  externals: {
    fsevents: 'require("fsevents")',
    worker_threads: 'require("worker_threads")'
  },

  node: {
    __dirname: false,
    __filename: false
  },

  resolve: {
    alias: {
      src: path.join(__dirname, '../..', 'src'),
      '@renderer': path.join(__dirname, '../..', 'src/renderer'),
      '@shared': path.join(__dirname, '../..', 'src/shared'),
      '@main': path.join(__dirname, '../..', 'src/main')
    },
    extensions: ['.webpack.js', '.web.js', '.ts', '.tsx', '.js', '.json'],
    mainFields: ['module', 'main']
  },

  plugins: [
    new HtmlWebpackPlugin({
      template: path.join(__dirname, '../..', 'src/index.html'),
      chunks: ['renderer'],
      filename: 'index.html'
    })
  ],

  module: {
    rules: [
      {
        test: /\.(jpg|png|svg|eot|ttf|woff|woff2)$/,
        loader: 'file-loader',
        options: {
          name: '[path][name].[ext]'
        }
      },
      {
        test: /\.tsx?$/,
        loaders: ['ts-loader']
      },
      {
        test: /\.css$/,
        loaders: ['style-loader', 'css-loader']
      }
    ]
  }
}

export default [main, renderer]
