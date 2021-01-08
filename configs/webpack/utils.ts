import cla from 'command-line-args'

interface ArgOptions {
  devport: number
  usertype: string
}

const optionDefinitions = [
  { name: 'usertype', alias: 'u', type: String },
  { name: 'devport', alias: 'd', type: Number },
  { name: 'config', type: String }
]
const options = cla(optionDefinitions)

export const args: ArgOptions = {
  devport: options.devport || 8001,
  usertype: options.usertype || 'default'
}
