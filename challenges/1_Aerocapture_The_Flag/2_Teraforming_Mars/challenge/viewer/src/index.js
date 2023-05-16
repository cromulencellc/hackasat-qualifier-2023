import "cesium/Build/Cesium/Widgets/widgets.css";
import "../src/css/main.css"

import { Transforms, Ion, Viewer, Ellipsoid, Matrix4, Matrix3, Cartesian3, Math, JulianDate,CzmlDataSource, defined,SceneMode,GeographicProjection,Globe,GeographicTilingScheme,WebMapServiceImageryProvider } from "cesium";

// Setup the Mars

var ellipsoidMars = new Ellipsoid(3396000,3396000,3396000);
var mapProjectionMars = new GeographicProjection(ellipsoidMars);
var globeMars = new Globe(ellipsoidMars);

var optsMars = {
    mapProjection: mapProjectionMars,
    globe: globeMars,
    baseLayerPicker: false
};
var viewer = new Viewer('cesiumContainer', optsMars);

var imageryLayers = viewer.imageryLayers;
imageryLayers.addImageryProvider(new WebMapServiceImageryProvider({
    url : 'https://planetarymaps.usgs.gov/cgi-bin/mapserv?map=/maps/mars/mars_simp_cyl.map&service=WMS',
    layers : 'MDIM21_color',
    parameters : {
        transparent : true,
        format : 'image/png'
    },
    tilingScheme: new GeographicTilingScheme({ ellipsoid: ellipsoidMars }),
    tileWidth: 512,
    tileHeight: 512
}));

//scene.skyBox.destroy();
//scene.skyBox = undefined;
//scene.sun.destroy();
//scene.sun = undefined;
//scene.backgroundColor = Color.BLACK.clone();

var czmlDataSource2 = new CzmlDataSource();
czmlDataSource2.load("czml/satellite.czml");
viewer.dataSources.add(czmlDataSource2);   

function icrf(scene, time) {
  if (scene.mode !== SceneMode.SCENE3D) {
      return;
  }

  var icrfToFixed = Transforms.computeIcrfToFixedMatrix(time);
  if (defined(icrfToFixed)) {
      var camera = viewer.camera;
      var offset = Cartesian3.clone(camera.position);
      var transform = Matrix4.fromRotationTranslation(icrfToFixed);
      camera.lookAtTransform(transform, offset);
  }
}

viewer.scene.postUpdate.addEventListener(icrf);

