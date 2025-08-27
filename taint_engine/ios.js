import { init_taint, start_taint, stop_taint, stalker_unfollow_at_addr} from "./taint_engine.js";
// source, sink

var MODULE_NAME = "iostest";

Stalker.unfollow();
Interceptor.detachAll();
console.log("Script loaded successfully ");


var found_module = Process.findModuleByName(MODULE_NAME);
var processData = found_module.findExportByName("nativeProcess");
var source = found_module.findSymbolByName("_ZL11source_modePKcmPcPmib");
var sink = found_module.findSymbolByName("_ZL9sink_modePcmi");

console.log(found_module.name, found_module.base, processData, source, sink);


// stalker_unfollow_at_addr(found_module.base.add(0x000a7a20))

Interceptor.attach(processData, {
    onEnter: function (args) {
        console.log(`processData at ${found_module.name} ${found_module.base} ${this.context.pc}`);
        init_taint(source, sink);
        start_taint();
    },
});

Interceptor.attach(sink, {
    
    onEnter: function (args) {
        console.log(`sink hit at ${found_module.name} ${found_module.base} ${this.context.pc}`);
        stop_taint();
    },
});